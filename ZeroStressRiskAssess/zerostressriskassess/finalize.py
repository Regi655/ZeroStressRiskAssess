"""Phase 2 of the report: review applied, encryption, signature, delivery.

FLOW
  1. `zsra HOST ...` writes a plaintext DRAFT on the controller only (report.json/.md/.html and
     report.json.sha256, mode 600, folder 700). The draft says it is a draft.
  2. You read it. If a detail is too dangerous to circulate (for example the exact path of a credentials
     file), note its ID: a finding (F012) or a whole problem of the risk table (R03).
  3. `zsra-finalize DRAFT_DIR --recipient ... --sign-key ...`:
       - applies the omissions: the detail disappears, the finding stays, and the report says what was
         omitted and why (a hidden omission would make the report false);
       - encrypts with age for the recipient(s): only the holder of the private key can read it;
       - signs with your SSH key (ssh-keygen -Y sign): anyone can verify it comes from you, unaltered;
       - writes manifest.json with the hashes of the draft and of the final version;
       - with --upload, copies to the target ONLY the encrypted file, the signature and the instructions.

WHY age + SSH signature: age gives confidentiality, but it does not say WHO encrypted: anyone who knows the
recipient's public key can produce a file encrypted for them. The signature adds authenticity. Two small
tools, each doing one thing: easier to understand and to verify.
"""
from __future__ import annotations

import argparse
import copy
import getpass
import hashlib
import io
import json
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime
from pathlib import Path

from .htmlreport import to_html
from .report import FINAL_STAGE, to_markdown, write_private, write_private_bytes
from .validate import valid_host

NAMESPACE = "zsra-report"   # SSH signatures are valid only for this "use" (never as a login)
AGE_RECIPIENT_RE = re.compile(r"age1[0-9a-z]{58}")
SSH_RECIPIENT_RE = re.compile(r"(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/=]{40,}( .*)?")
FINDING_RE = re.compile(r"F\d{3,5}")
RISK_RE = re.compile(r"R\d{2,3}")
# Specific parts of a title: absolute paths and quoted names ("... readable by others: /home/dev/.ssh/id_ed25519",
# "Home directory of 'dev2' ..."). Titles carry them too, not only the details.
TITLE_SPECIFIC = [re.compile(r"(?<![\w.])/[^\s,;)]+"), re.compile(r"'[^']+'")]


def generic_title(title: str) -> str:
    """Title without paths and quoted names: the kind of weakness stays, the exact location goes."""
    for rx in TITLE_SPECIFIC:
        title = rx.sub("[omitted]", title)
    return title


class FinalizeError(RuntimeError):
    pass


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _need(tool: str):
    if not shutil.which(tool):
        hint = {"age": "sudo apt install age  (Fedora/Rocky with EPEL: sudo dnf install age; Arch: sudo pacman -S age)",
                "ssh-keygen": "sudo apt install openssh-client"}[tool]
        raise FinalizeError(f"'{tool}' not found on the controller. Install it: {hint}")


def recipient_args(recipients) -> list:
    """Each recipient can be an age key (age1...), an SSH public key, or a file containing them."""
    out = []
    for r in recipients:
        r = r.strip()
        if AGE_RECIPIENT_RE.fullmatch(r) or SSH_RECIPIENT_RE.fullmatch(r):
            out += ["-r", r]
        elif Path(r).expanduser().is_file():
            out += ["-R", str(Path(r).expanduser())]
        else:
            raise FinalizeError(f"Invalid recipient: {r[:40]}... (expected age1..., ssh-ed25519 ... or a file)")
    if not out:
        raise FinalizeError("At least one --recipient is needed")
    return out


def apply_omissions(rep: dict, omit_ids, reason: str) -> list:
    """Remove the DETAILS of the given findings and record it. Severity and the kind of weakness stay; paths and
    quoted names are removed from the titles too (finding and risk-table row), because titles carry them as well.

    F012 = one finding; R03 = every finding that is evidence of problem R03 in the risk table.
    The raw output and the collected data of the affected check are removed too: the detail may appear there.
    """
    wanted = set(omit_ids)
    bad = [i for i in wanted if not (FINDING_RE.fullmatch(i) or RISK_RE.fullmatch(i))]
    if bad:
        raise FinalizeError(f"Invalid IDs: {', '.join(sorted(bad))} (expected a finding F012 or a problem R03)")
    found, omissions = set(), []
    for sc in rep["scans"]:
        hit = False
        for f in sc["findings"]:
            ids = {f.get("id"), f.get("issue")} & wanted
            if not ids:
                continue
            found |= ids
            f["detail"] = f"[detail omitted in review: {reason}]"
            f["title"] = generic_title(f["title"])
            omissions.append({"id": f["id"], "problem": f.get("issue"), "scan": sc["name"],
                              "severity": f["severity"], "title": f["title"], "reason": reason})
            hit = True
        if hit:
            if sc.get("raw"):
                sc["raw"] = "[raw output removed: it contained details omitted in review]"
            if sc.get("data"):
                sc["data"] = {"omitted": "collected data removed: it contained details omitted in review"}
    missing = wanted - found
    if missing:
        raise FinalizeError(f"IDs not in the report: {', '.join(sorted(missing))}")
    touched = {o["problem"] for o in omissions if o["problem"]}
    for r in rep.get("risks", []):
        if r["id"] in touched:
            r["title"] = generic_title(r["title"])
    rep["omissions"] = omissions
    return omissions


def _tar_bytes(files: dict) -> bytes:
    """tar.gz built in memory (no extra plaintext copies on disk)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content if isinstance(content, bytes) else content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o600, 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def find_draft(draft_dir) -> Path:
    """Draft folder. The path of report.json is accepted too. If not found, the error lists the drafts nearby
    (the most common mistake: launched from another folder)."""
    d = Path(draft_dir).expanduser()
    if d.name == "report.json" and d.is_file():
        d = d.parent
    if (d / "report.json").is_file():
        return d
    near = d.parent if d.parent.is_dir() else Path("reports")
    found = sorted(str(p.parent) for p in near.glob("*/report.json"))[-10:] if near.is_dir() else []
    hint = ("Drafts found in " + str(near.resolve()) + ":\n  " + "\n  ".join(found)) if found else \
        f"No draft in {near.resolve()}. Are you in the folder the assessment was launched from? (pwd)"
    raise FinalizeError(f"{d.resolve()}/report.json not found.\n{hint}")


def finalize(draft_dir, recipients, sign_key=None, omit=(), reason="", log=print) -> dict:
    """Run phase 2. Returns the manifest (with the paths of the files produced)."""
    _need("age")
    d = find_draft(draft_dir)
    draft_text = (d / "report.json").read_text(encoding="utf-8")
    draft_sha = _sha(draft_text)
    shaf = d / "report.json.sha256"
    recorded = shaf.read_text().split()[0] if shaf.is_file() else None
    modified = recorded is not None and recorded != draft_sha
    if modified:
        log("[!] The draft was modified after the assessment (different hash): recorded in the manifest.")
    if omit and not reason.strip():
        raise FinalizeError("--omit requires --reason (the report must say WHY a detail is missing)")
    age_args = recipient_args(recipients)

    final = copy.deepcopy(json.loads(draft_text))
    omissions = apply_omissions(final, omit, reason.strip()) if omit else []
    final["meta"]["stage"] = FINAL_STAGE
    final["meta"]["finalized"] = datetime.now().isoformat(timespec="seconds")
    final["meta"]["draft_sha256"] = draft_sha
    final_js = json.dumps(final, indent=2, ensure_ascii=False)
    final_md, final_html = to_markdown(final), to_html(final)

    out = d / "final"
    out.mkdir(exist_ok=True)
    out.chmod(0o700)
    write_private(out / "report-final.json", final_js)
    write_private(out / "report-final.md", final_md)
    write_private(out / "report-final.html", final_html)

    # Encryption: tar.gz in memory -> age. -a = "armored" (ASCII text): it uploads as text and can be pasted
    # into an e-mail without being damaged.
    enc = out / f"report-{d.name}.tar.gz.age"
    log(f"[+] Encrypting with age for {len(recipients)} recipient(s)...")
    files = {"report.json": final_js, "report.md": final_md, "report.html": final_html}
    from . import pdfreport
    if pdfreport.available():   # the final version as PDF too: what the recipient most likely forwards or prints
        files["report.pdf"] = pdfreport.pdf_bytes(final)
        write_private_bytes(out / "report-final.pdf", files["report.pdf"])
    blob = _tar_bytes(files)
    p = subprocess.run(["age", "-a", *age_args, "-o", str(enc)], input=blob, capture_output=True)
    if p.returncode != 0:
        raise FinalizeError("age failed: " + p.stderr.decode(errors="replace")[:300])
    enc.chmod(0o600)
    enc_sha = hashlib.sha256(enc.read_bytes()).hexdigest()

    manifest = {
        "created": final["meta"]["finalized"], "target": final["meta"].get("target"),
        "draft_sha256": draft_sha, "draft_modified_after_scan": modified,
        "final_json_sha256": _sha(final_js), "encrypted_file": enc.name, "encrypted_sha256": enc_sha,
        "recipients": list(recipients), "omissions": [{"id": o["id"], "reason": o["reason"]} for o in omissions],
        "signature_file": None, "signer": None,
    }

    if sign_key:
        _need("ssh-keygen")
        key = Path(sign_key).expanduser()
        pub = Path(str(key) + ".pub")
        if not pub.is_file():
            raise FinalizeError(f"Public key {pub} missing (needed for the verification instructions)")
        sig = Path(str(enc) + ".sig")
        # An old signature must go FIRST: if it exists, ssh-keygen asks "Overwrite (y/n)?" (a question we would
        # not see, because its output is captured), and without a "y" it keeps the OLD signature and still exits
        # 0. Seen in the lab: new file + signature of the previous file = "Signature verification failed".
        sig.unlink(missing_ok=True)
        log("[+] Signing the encrypted file (ssh-keygen may ask for the key passphrase)...")
        # stdout/stderr captured (only "Signing file..."); ssh-keygen asks the passphrase on the terminal.
        r = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", NAMESPACE, str(enc)],
                           capture_output=True, text=True)
        if r.returncode != 0 or not sig.is_file():
            raise FinalizeError("Signing failed (ssh-keygen -Y sign): " + r.stderr.strip()[:300])
        sig.chmod(0o600)   # ssh-keygen creates it 644: same mode as the other files
        pubkey = " ".join(pub.read_text().split()[:2])
        write_private(out / "allowed_signers", f"zsra {pubkey}\n")
        # Immediate verification, as the recipient will do it. The exit code of an external program is not
        # trusted: the result is checked. If it fails, NOTHING is delivered.
        if not verify_signature(out, enc):
            raise FinalizeError("The signature just created does NOT verify: the file is not delivered.")
        log("    signature verified: Good.")
        manifest.update({"signature_file": sig.name, "signer": pubkey})

    write_private(out / "manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
    write_private(out / "README-recipient.txt", recipient_instructions(enc.name, bool(sign_key)))
    manifest["paths"] = {"dir": str(out), "encrypted": str(enc)}
    return manifest


def verify_signature(out: Path, enc: Path) -> bool:
    """ssh-keygen -Y verify with allowed_signers: True only if the signature matches the file."""
    with open(enc, "rb") as data:
        r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(out / "allowed_signers"), "-I", "zsra",
                            "-n", NAMESPACE, "-s", str(enc) + ".sig"], stdin=data, capture_output=True)
    return r.returncode == 0


def recipient_instructions(enc_name: str, signed: bool) -> str:
    s = [f"Risk assessment report: {enc_name}", "",
         "The file is encrypted: only the holder of the private key matching the public key provided",
         "can read it. You need the programs 'age' and (for the verification) 'ssh-keygen'.", ""]
    if signed:
        s += ["1) VERIFY that the file comes from the author and was not altered (a single line, copy all of it):",
              f"   ssh-keygen -Y verify -f allowed_signers -I zsra -n {NAMESPACE} -s {enc_name}.sig < {enc_name}",
              f"   It must print: Good \"{NAMESPACE}\" signature for zsra ...",
              "   If the verification fails, do NOT open the file and contact the author.", ""]
    s += [f"{'2' if signed else '1'}) DECRYPT and extract (age key):",
          f"   age -d -i YOUR_PRIVATE_KEY.txt {enc_name} | tar xzf -",
          "   With an SSH key instead of an age key: age -d -i ~/.ssh/id_ed25519 ...",
          "", "You get report.html (to read in a browser), report.pdf (to print or forward, when present), "
          "report.md and report.json (complete data).",
          "Keep the decrypted files on an encrypted disk: they describe the weaknesses of the system."]
    return "\n".join(s) + "\n"


def load_finalized(draft_dir) -> dict:
    """For --upload-only: re-read the manifest of a phase 2 already done and re-check the encrypted file (hash and
    signature) BEFORE uploading it. A failed upload does not force encryption and signing to be redone."""
    out = find_draft(draft_dir) / "final"
    mf = out / "manifest.json"
    if not mf.is_file():
        raise FinalizeError(f"{mf} not found: run phase 2 without --upload-only first")
    m = json.loads(mf.read_text(encoding="utf-8"))
    enc = out / m["encrypted_file"]
    if not enc.is_file() or hashlib.sha256(enc.read_bytes()).hexdigest() != m["encrypted_sha256"]:
        raise FinalizeError(f"{enc.name} missing or different from the manifest: redo phase 2")
    if m.get("signature_file") and not verify_signature(out, enc):
        raise FinalizeError("The signature does not match the encrypted file: redo phase 2")
    m["paths"] = {"dir": str(out), "encrypted": str(enc)}
    return m


def upload(rem, manifest: dict, log=print) -> str:
    """Copy to the target ONLY the encrypted file, signature, verification key and instructions. Checks the hash."""
    out = Path(manifest["paths"]["dir"])
    names = [manifest["encrypted_file"], "README-recipient.txt"]
    if manifest.get("signature_file"):
        names += [manifest["signature_file"], "allowed_signers"]
    log(f"[+] Connecting to {rem.user}@{rem.host}:{rem.port} for the upload...")
    try:
        rem.connect()
    except Exception as exc:   # paramiko: network, authentication and host-key errors
        raise FinalizeError(_connect_hint(rem, exc) + f"\nThe encrypted file is ready in {out}: when the target is "
                            "reachable, repeat with --upload-only (no new encryption or signature).") from None
    try:
        rdir = f"{rem.home()}/zsra_reports/{manifest['encrypted_file'].removesuffix('.tar.gz.age')}"
        q = shlex.quote(rdir)
        rem.run(f"mkdir -p {q} && chmod 700 {q}")
        for n in names:
            rem.upload_text(f"{rdir}/{n}", (out / n).read_text(encoding="utf-8"))
            rem.run(f"chmod 600 {shlex.quote(rdir + '/' + n)}")
        remote_sha = rem.run(f"sha256sum {shlex.quote(rdir + '/' + manifest['encrypted_file'])} | cut -d' ' -f1").out.strip()
        if remote_sha != manifest["encrypted_sha256"]:
            raise FinalizeError("The hash of the uploaded file differs from the original: upload NOT reliable")
        log(f"[+] Uploaded to the target (encrypted only): {rdir}")
        return rdir
    finally:
        rem.close()


def _connect_hint(rem, exc) -> str:
    """An understandable message instead of the paramiko traceback."""
    name, text = type(exc).__name__, str(exc)
    where = f"{rem.host}:{rem.port}"
    if "NoValidConnections" in name or isinstance(exc, (ConnectionError, TimeoutError)) or "timed out" in text:
        return f"{where} does not answer: target off, wrong IP or port closed. Try: nc -zv {rem.host} {rem.port}"
    if "Authentication" in name:
        return f"Access refused for {rem.user}@{rem.host}: key not authorised or wrong password."
    if "HostKey" in name or "not found in known_hosts" in text:
        return (f"Host key of {rem.host} unknown or CHANGED. Check the fingerprint and connect once with ssh "
                "(or use --accept-new-hostkey on the first connection).")
    return f"Connection to {where} failed ({name}: {text[:200]})"


def build_parser():
    ap = argparse.ArgumentParser(prog="zsra-finalize",
                                 description="Report phase 2: omissions, encryption (age), signature (SSH), delivery")
    ap.add_argument("draft_dir", help="draft folder (contains report.json)")
    ap.add_argument("--recipient", action="append", default=[],
                    help="recipient public key: age1..., 'ssh-ed25519 AAAA...' or a file (repeatable)")
    ap.add_argument("--sign-key", help="YOUR SSH private key, to sign (e.g. ~/.ssh/id_ed25519)")
    ap.add_argument("--omit", action="append", default=[], metavar="ID",
                    help="finding (F012) or problem (R03) whose details are omitted (repeatable)")
    ap.add_argument("--reason", default="", help="reason for the omissions (required with --omit)")
    ap.add_argument("--upload", action="store_true", help="copy ONLY the encrypted file to the target")
    ap.add_argument("--upload-only", action="store_true",
                    help="upload a phase 2 ALREADY done (after a failed upload), without encrypting and signing again")
    ap.add_argument("--host", help="target to upload the encrypted file to (with --upload)")
    ap.add_argument("-u", "--user", help="SSH user on the target (with --upload)")
    ap.add_argument("-p", "--port", type=int, default=22)
    ap.add_argument("-i", "--key", help="SSH key to connect to the target (with --upload)")
    ap.add_argument("--ask-pass", action="store_true", help="prompt for the SSH password")
    ap.add_argument("--ask-key-pass", action="store_true", help="prompt for the passphrase of the -i key")
    ap.add_argument("--accept-new-hostkey", action="store_true")
    return ap


def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.upload_only and not args.recipient:
        ap.error("at least one --recipient is needed (or --upload-only to upload a phase 2 already done)")
    if (args.upload or args.upload_only) and not (args.host and args.user):
        ap.error("--upload requires --host and -u")
    if args.host and not valid_host(args.host):
        ap.error(f"invalid host: {args.host}")
    if not args.sign_key and not args.upload_only:
        print("[!] No --sign-key: the file will be encrypted but NOT signed (the recipient cannot verify it comes "
              "from you).", file=sys.stderr)
    try:
        if args.upload_only:
            m = load_finalized(args.draft_dir)
            print(f"[+] Phase 2 already done, file intact{' and signature valid' if m.get('signature_file') else ''}: "
                  f"{m['paths']['encrypted']}")
        else:
            m = finalize(args.draft_dir, args.recipient, args.sign_key, args.omit, args.reason)
            print(f"[+] Encrypted: {m['paths']['encrypted']}")
            print(f"    SHA-256: {m['encrypted_sha256']}")
            if m["omissions"]:
                print(f"    Omitted: {', '.join(o['id'] for o in m['omissions'])}")
        if args.upload or args.upload_only:
            from .ssh_client import Remote
            kp = getpass.getpass("Key passphrase: ") if args.ask_key_pass else None
            pw = getpass.getpass("SSH user password: ") if args.ask_pass else None
            key = str(Path(args.key).expanduser()) if args.key else None
            upload(Remote(args.host, args.user, args.port, key, pw, None, args.accept_new_hostkey, passphrase=kp), m)
    except FinalizeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
