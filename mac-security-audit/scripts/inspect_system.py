#!/usr/bin/env python3
"""Bounded macOS security metadata inspection. No elevation or remediation."""
import argparse
import csv
import datetime as dt
import io
import itertools
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import time


def run(argv, timeout=15):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout)
        return {"status": "ok" if p.returncode == 0 else "unavailable", "returncode": p.returncode,
                "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "stdout": "", "stderr": "bounded query timed out"}
    except OSError as e:
        return {"status": "unavailable", "stdout": "", "stderr": type(e).__name__}


def basic_query(argv, timeout=15):
    result = run(argv, timeout)
    return {"status": result["status"], "result": (result["stdout"] + result["stderr"]).strip()[:16000]}


def backup_destinations():
    r = run(["/usr/bin/tmutil", "destinationinfo"])
    # Never retain destination URLs, names or IDs: a URL can contain credentials.
    kinds = re.findall(r"^Kind\s*:\s*(.+)$", r["stdout"], re.M)
    combined = r["stdout"] + r["stderr"]
    none_configured = True if "No destinations configured" in combined else False if r["status"] == "ok" and kinds else None
    return {"status": r["status"], "no_destinations_configured": none_configured,
            "destination_count": len(kinds), "kinds": kinds,
            "limitation": "Destination identifiers, URLs and names omitted; no destination mounted or backup initiated."}


def extract(path, key):
    r = run(["/usr/bin/plutil", "-extract", key, "raw", "-o", "-", str(path)], 3)
    return r["stdout"].strip() if r["status"] == "ok" else None


def file_metadata(path):
    try:
        if any(p.is_symlink() for p in path.absolute().parents):
            return {"path": str(path), "status": "skipped_symlink_parent"}
        s = path.lstat()
        result = {"path": str(path), "bytes": s.st_size, "mode": stat.filemode(s.st_mode),
                  "owner_uid": s.st_uid, "mtime": dt.datetime.fromtimestamp(s.st_mtime, dt.timezone.utc).isoformat(),
                  "symlink": stat.S_ISLNK(s.st_mode), "group_writable": bool(s.st_mode & stat.S_IWGRP),
                  "world_writable": bool(s.st_mode & stat.S_IWOTH)}
        if not result["symlink"]:
            try:
                if hasattr(os, "listxattr"):
                    attrs = os.listxattr(path, follow_symlinks=False)
                    result["quarantine_attribute_present"] = "com.apple.quarantine" in attrs
                else:
                    attrs = run(["/usr/bin/xattr", str(path)], 3)
                    result["quarantine_attribute_present"] = "com.apple.quarantine" in attrs["stdout"].splitlines() if attrs["status"] == "ok" else None
            except OSError:
                result["quarantine_attribute_present"] = None
        return result
    except OSError as e:
        return {"path": str(path), "status": "unavailable", "error": type(e).__name__}


def startup(home):
    rows, unreadable, coverage = [], [], []
    loaded = {}
    result = run(["/bin/launchctl", "list"])
    for line in result["stdout"].splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) == 3:
            loaded[parts[2]] = {"pid": parts[0], "last_exit": parts[1]}
    for root in [home / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]:
        try:
            if root.is_symlink() or any(p.is_symlink() for p in root.absolute().parents):
                coverage.append({"root": str(root), "status": "skipped_symlink"})
                continue
            entries = list(itertools.islice(root.iterdir(), 2001))
            paths = sorted(p for p in entries[:2000] if p.suffix == '.plist')
            coverage.append({"root": str(root), "status": "partial_due_to_limit" if len(entries) > 2000 or len(paths) > 500 else "listed", "plist_candidates": len(paths)})
        except FileNotFoundError:
            coverage.append({"root": str(root), "status": "absent"})
            continue
        except OSError as error:
            unreadable.append(str(root))
            coverage.append({"root": str(root), "status": "unavailable", "error_type": type(error).__name__})
            continue
        for path in paths[:500]:
            row = file_metadata(path)
            if not row.get("mode", "").startswith('-') and not row.get("symlink"):
                row["inspection"] = "not a regular readable-path plist; not opened"
                rows.append(row)
                continue
            if row.get("symlink"):
                row["inspection"] = "symlink not followed"
                rows.append(row)
                continue
            for key in ["Label", "Program", "ProgramArguments.0", "RunAtLoad", "KeepAlive", "Disabled", "StartInterval"]:
                value = extract(path, key)
                if value is not None:
                    row[key] = value
            if row.get("Label") in loaded:
                row["loaded_in_current_user"] = loaded[row["Label"]]
            rows.append(row)
    return {"items": rows, "unreadable": unreadable, "coverage": coverage,
            "limitation": "Launch plists only; app login/background registrations require a separate System Settings review. Environment variables and remaining arguments were not read."}


def listeners():
    r = run(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"], 15)
    rows = []
    pid, command = None, None
    for line in r["stdout"].splitlines():
        if line.startswith("p"):
            pid = line[1:]
        elif line.startswith("c"):
            command = line[1:]
        elif line.startswith("n"):
            endpoint = line[1:]
            host, _, port = endpoint.rpartition(":")
            if not port.isdigit():
                continue
            bind = "loopback" if host in ["127.0.0.1", "[::1]", "::1"] else "all_interfaces" if host in ["*", "0.0.0.0", "[::]"] else "specific_local_interface"
            row = {"pid": pid, "process": command, "port": int(port), "bind": bind}
            if row not in rows:
                rows.append(row)
    return {"status": r["status"], "items": rows,
            "limitation": "Only visible TCP listeners. No remote endpoints or packets collected; listener presence does not prove Internet reachability."}


def network_sample(seconds):
    if seconds == 0:
        return {"status": "skipped", "reason": "network-seconds is 0"}
    r = run(["/usr/bin/nettop", "-P", "-L", "2", "-s", str(seconds), "-n", "-x", "-t", "external", "-J", "bytes_in,bytes_out"], seconds + 15)
    samples, current = [], None
    for row in csv.reader(io.StringIO(r["stdout"])):
        if len(row) >= 3 and row[1] == "bytes_in":
            current = {}
            samples.append(current)
        elif current is not None and len(row) >= 3:
            try:
                current[row[0]] = (int(row[1]), int(row[2]))
            except ValueError:
                pass
    deltas = []
    if len(samples) >= 2:
        for proc in samples[0].keys() & samples[-1].keys():
            before, after = samples[0][proc], samples[-1][proc]
            if after[0] < before[0] or after[1] < before[1]:
                continue
            incoming, outgoing = after[0] - before[0], after[1] - before[1]
            if incoming or outgoing:
                deltas.append({"process_pid": proc, "received_bytes": incoming, "sent_bytes": outgoing})
    return {"status": "ok" if len(samples) >= 2 else "unavailable", "interval_seconds": seconds,
            "top_active_processes": sorted(deltas, key=lambda x: x["sent_bytes"] + x["received_bytes"], reverse=True)[:20],
            "limitation": "Two short samples on non-loopback interfaces, including LAN; no historical transfers, destinations or payloads. Volume alone cannot identify exfiltration. Newly appearing/disappearing processes are omitted from deltas."}


def login_summary():
    r = run(["/usr/bin/last", "-20"], 10)
    lines = [x for x in r["stdout"].splitlines() if x.strip() and not x.startswith("wtmp")]
    return {"status": r["status"], "records_returned": len(lines),
            "console_records": sum(" console " in x for x in lines),
            "terminal_records": sum(bool(re.search(r"\bttys?\d*", x)) for x in lines),
            "reboot_records": sum(x.startswith("reboot") for x in lines),
            "shutdown_records": sum(x.startswith("shutdown") for x in lines),
            "limitation": "Aggregate last 20 records only; usernames, hosts and raw lines omitted. This is not failed-login coverage and cannot establish absence of unauthorized access. Shell/browser/chat histories are not inspected."}


def remote_and_network_settings():
    r = run(["/bin/launchctl", "print-disabled", "system"])
    service_overrides = {}
    for label in ["com.openssh.sshd", "com.apple.screensharing", "com.apple.smbd", "com.apple.RemoteDesktop.PrivilegeProxy"]:
        m = re.search('"' + re.escape(label) + r'"\s*=>\s*(enabled|disabled)', r["stdout"])
        service_overrides[label] = m.group(1) if m else "no explicit override; unknown"
    p = run(["/usr/sbin/scutil", "--proxy"])
    flags = {}
    for key in ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"]:
        m = re.search(r"\b" + key + r"\s*:\s*(\d+)", p["stdout"])
        flags[key] = int(m.group(1)) if m else "not explicitly present"
    return {"remote_service_overrides": service_overrides,
            "proxy_enable_flags": flags,
            "mdm_enrollment": basic_query(["/usr/bin/profiles", "status", "-type", "enrollment"]),
            "system_extensions": basic_query(["/usr/bin/systemextensionsctl", "list"]),
            "limitation": "An absent launchctl override is unknown, not disabled. Proxy endpoints, PAC URLs and credentials were omitted."}


def signature_metadata(path):
    verify = run(["/usr/bin/codesign", "--verify", "--strict", str(path)], 8)
    details = run(["/usr/bin/codesign", "-dv", "--verbose=2", str(path)], 5)
    data = {"verification": verify["status"], "limitation": "Integrity check only; ad-hoc signatures do not establish a publisher, and a valid signature is not a malware verdict or notarization check."}
    for line in (details["stdout"] + details["stderr"]).splitlines():
        if line.startswith(("Identifier=", "TeamIdentifier=", "Authority=", "Signature=")):
            key, value = line.split("=", 1)
            data.setdefault(key, []).append(value)
    if verify["status"] != "ok":
        text = verify["stderr"].lower()
        data["reason"] = "unsigned" if "not signed at all" in text else "signature validation unavailable or failed; manual review"
    return data


def file_checks(home, days):
    cutoff = time.time() - days * 86400
    root = home / "Downloads"
    recent, errors, inspected = [], [], 0
    try:
        linked = root.is_symlink() or any(p.is_symlink() for p in root.absolute().parents)
        candidates = [] if linked else list(itertools.islice(root.iterdir(), 2001))
        if linked:
            errors.append("Downloads or a parent is a symlink; not followed")
        if len(candidates) > 2000:
            errors.append("Downloads entry limit reached; coverage partial")
            candidates = candidates[:2000]
        for path in list(candidates):
            if len(candidates) >= 2000:
                errors.append("Downloads total entry limit reached; child directories not fully inspected")
                break
            if path.is_dir() and not path.is_symlink() and path.suffix.lower() not in [".app", ".pkg", ".bundle"]:
                try:
                    child_entries = list(itertools.islice(path.iterdir(), 201))
                    if len(child_entries) > 200:
                        errors.append(str(path) + ": child entry limit reached")
                    room = min(200, 2000 - len(candidates))
                    candidates.extend(child_entries[:room])
                except OSError:
                    errors.append(str(path))
        for path in candidates[:2000]:
            inspected += 1
            row = file_metadata(path)
            if "mtime" not in row or row.get("symlink"):
                continue
            if path.lstat().st_mtime < cutoff:
                continue
            suffix = path.suffix.lower()
            reasons = []
            if "\u202e" in path.name or "\u202d" in path.name:
                reasons.append("bidirectional-control-character-in-name")
            if re.search(r"\.(?:pdf|docx?|xlsx?|jpe?g|png|txt)\.(?:app|pkg|command|sh|js|py|dmg)$", path.name, re.I):
                reasons.append("document-like-double-extension")
            if suffix in [".app", ".pkg", ".dmg", ".command", ".sh", ".js", ".py", ".workflow", ".mobileconfig"]:
                reasons.append("recent-installable-or-executable-type")
            if row.get("world_writable"):
                reasons.append("world-writable")
            if reasons:
                row["review_reasons"] = reasons
                recent.append(row)
    except OSError as e:
        errors.append(type(e).__name__)
    apps, signature_budget = [], 10
    try:
        app_paths = sorted(p for p in Path("/Applications").iterdir() if p.suffix == '.app')
        if len(app_paths) > 300:
            errors.append("Applications limit reached; coverage partial")
        for path in app_paths[:300]:
            row = file_metadata(path)
            reasons = []
            if row.get("world_writable"):
                reasons.append("world-writable-app-bundle")
            if not row.get("symlink") and path.lstat().st_mtime >= cutoff:
                reasons.append("app-bundle-recently-modified")
            if reasons:
                row["review_reasons"] = reasons
                if signature_budget and not row.get("symlink"):
                    row["signature"] = signature_metadata(path)
                    signature_budget -= 1
                apps.append(row)
    except OSError as e:
        errors.append(type(e).__name__)
    sensitive = []
    paths = [home / ".env", home / ".codex/auth.json", home / ".ssh"]
    ssh = home / ".ssh"
    try:
        if ssh.is_dir() and not ssh.is_symlink():
            for name in ["id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "config"]:
                paths.append(ssh / name)
    except OSError as error:
        errors.append(str(ssh) + ": " + type(error).__name__)
    for path in paths:
        try:
            path.lstat()
            row = file_metadata(path)
            row.pop("quarantine_attribute_present", None)
            if "mode" in row and not row.get("symlink"):
                mode = path.stat().st_mode
                row["group_or_other_access"] = bool(mode & 0o077)
            sensitive.append(row)
        except FileNotFoundError:
            continue
        except OSError as error:
            sensitive.append({"path": str(path), "status": "unavailable", "error_type": type(error).__name__})
    return {"days": days, "download_entries_considered": inspected, "download_review_items": recent,
            "application_review_items": apps, "sensitive_path_permissions_only": sensitive, "errors": errors,
            "limitation": "Metadata-only, bounded Downloads depth 1 / first 2000 entries, 200 children per directory, top-level /Applications bundles. Recent/installable/unsigned does not mean malicious. No document/archive contents, secrets, payload execution, malware scan or uploads."}


def collect(home, days=14, network_seconds=3, updates=False):
    if platform.system() != "Darwin":
        return {"status": "unsupported", "reason": "This module supports macOS only."}
    system = {}
    commands = {
        "macos": ["/usr/bin/sw_vers"], "filevault": ["/usr/bin/fdesetup", "status"],
        "firewall": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
        "firewall_stealth": ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
        "gatekeeper": ["/usr/sbin/spctl", "--status"], "sip": ["/usr/bin/csrutil", "status"],
        "authenticated_root": ["/usr/bin/csrutil", "authenticated-root", "status"],
        "time_machine_snapshots": ["/usr/bin/tmutil", "listlocalsnapshots", "/"],
        "update_schedule": ["/usr/sbin/softwareupdate", "--schedule"]}
    for key, command in commands.items():
        system[key] = basic_query(command)
    system["time_machine_destinations"] = backup_destinations()
    if updates:
        system["available_updates"] = basic_query(["/usr/sbin/softwareupdate", "--list"], 90)
    else:
        system["available_updates"] = {"status": "skipped", "reason": "Use --check-updates for the read-only Apple update catalog query."}
    return {"schema_version": 1, "module": "system", "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "scope": "Read-only metadata queries; no elevation or remediation. Only the requested report is intentionally written; operating-system query logs/caches may update normally.",
            "system": system, "startup": startup(home), "listeners": listeners(),
            "network_sample": network_sample(network_seconds), "login_records": login_summary(),
            "remote_and_network": remote_and_network_settings(), "files": file_checks(home, days),
            "unassessed": ["Historical network transfers and exfiltration", "Failed-logins / full audit log", "TCC app permissions", "Browser/login records outside this module", "Malware payloads or all filesystem contents"]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", type=Path, default=Path.home())
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--days", type=int, default=14, choices=range(1, 91), metavar="1..90")
    p.add_argument("--network-seconds", type=int, default=3, choices=range(0, 11), metavar="0..10")
    p.add_argument("--check-updates", action="store_true")
    args = p.parse_args()
    report = collect(args.home.expanduser(), args.days, args.network_seconds, args.check_updates)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # The sole intentional filesystem write is the caller-selected report.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(json.dumps({"output": str(args.output), "status": report.get("status", "completed")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
