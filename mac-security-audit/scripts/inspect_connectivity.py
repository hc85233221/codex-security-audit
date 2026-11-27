#!/usr/bin/env python3
"""Read-only macOS Wi-Fi, Bluetooth and app metadata; no scans or usage inference."""
import argparse
import datetime as dt
import itertools
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import subprocess
from xml.parsers.expat import ExpatError


MAX_QUERY_BYTES = 4 * 1024 * 1024
MAX_APPS = 300
WIFI_SCRIPT = r'''
ObjC.import("CoreWLAN");
var a = $.CWWiFiClient.sharedWiFiClient.interfaces.allObjects, out = [];
for (var i = 0; i < Math.min(Number(a.count), 8); i++) {
    var w = a.objectAtIndex(i);
    out.push({interface: ObjC.unwrap(w.interfaceName), power_on: Boolean(w.powerOn),
              security: Number(w.security), phy: Number(w.activePHYMode),
              mode: Number(w.interfaceMode), transmit_rate: Number(w.transmitRate)});
}
JSON.stringify(out);
'''
RUNNING_SCRIPT = r'''
ObjC.import("AppKit");
var a = $.NSWorkspace.sharedWorkspace.runningApplications, out = [];
for (var i = 0; i < Math.min(Number(a.count), 1000); i++) {
    var p = a.objectAtIndex(i);
    if (Number(p.activationPolicy) === 0) {
        out.push({name: ObjC.unwrap(p.localizedName), bundle_id: ObjC.unwrap(p.bundleIdentifier)});
    }
}
JSON.stringify(out);
'''
SECURITY = {0: "Open（無 Wi-Fi 加密）", 1: "WEP", 2: "WPA Personal",
            3: "WPA/WPA2 Personal 混合", 4: "WPA2 Personal", 5: "Personal（未細分）",
            6: "Dynamic WEP", 7: "WPA Enterprise", 8: "WPA/WPA2 Enterprise 混合",
            9: "WPA2 Enterprise", 10: "Enterprise（未細分）", 11: "WPA3 Personal",
            12: "WPA3 Enterprise", 13: "WPA2/WPA3 過渡模式", 14: "OWE", 15: "OWE 過渡模式"}
PHY = {0: "未知", 1: "802.11a", 2: "802.11b", 3: "802.11g", 4: "802.11n",
       5: "802.11ac", 6: "802.11ax"}


def safe_text(value, limit=180):
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return ""
    return re.sub(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]", "", str(value))[:limit]


def run_json(argv, timeout=20):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout)
        if p.returncode != 0:
            return {"status": "unavailable", "reason": "query_failed"}
        if len(p.stdout) > MAX_QUERY_BYTES:
            return {"status": "unavailable", "reason": "query_size_limit"}
        return {"status": "ok", "data": json.loads(p.stdout.decode("utf-8"))}
    except subprocess.TimeoutExpired:
        return {"status": "unavailable", "reason": "query_timeout"}
    except (OSError, UnicodeError, ValueError) as error:
        # Never retain command stderr: it can contain source paths or other data.
        return {"status": "unavailable", "reason": type(error).__name__}


def check(identifier, category, title, status, summary, evidence, actions=None,
          severity="info", impact="", limitations=None, terms=None):
    return {"id": identifier, "category": category, "title": title, "status": status,
            "severity": severity, "summary": summary, "impact": impact,
            "actions": actions or [], "evidence": evidence, "limitations": limitations or [],
            "terms": terms or []}


def wifi_checks(query=None):
    result = query if query is not None else run_json(["/usr/bin/osascript", "-l", "JavaScript", "-e", WIFI_SCRIPT])
    source = "CoreWLAN：powerOn / security / activePHYMode / interfaceMode / transmitRate"
    limits = ["只讀取目前介面的狀態，未掃描附近網路；不讀取或保存 Wi-Fi 名稱、基地台位址或密碼。",
              "未驗證基地台身分、路由器韌體、管理密碼、WPS 或對外可達性；加密類型不是整體網路安全認證。"]
    if result.get("status") != "ok" or not isinstance(result.get("data"), list):
        return [check("network.wifi", "network", "Wi-Fi 連線保護", "unknown", "無法取得目前 Wi-Fi 狀態。",
                      [{"source": source, "detail": "查詢未完成；沒有擴大存取權。"}],
                      ["在系統設定 → Wi-Fi 查看目前連線的安全性。"], limitations=limits, terms=["wifi_security"])], []
    if not result["data"]:
        return [check("network.wifi", "network", "Wi-Fi 連線保護", "not_checked", "本次未取得 Wi-Fi 介面。",
                      [{"source": source, "detail": "回傳介面數為 0；不是未連線或沒有風險的證明。"}], limitations=limits)], []
    checks, devices = [], []
    for i, row in enumerate(result["data"][:8]):
        if not isinstance(row, dict):
            continue
        power, sec, phy = row.get("power_on"), row.get("security"), row.get("phy")
        interface = safe_text(row.get("interface"), 32) or "介面 %s" % (i + 1)
        security = SECURITY.get(sec, "未知安全類型")
        protocol = PHY.get(phy, "其他／未知 PHY（%s）" % safe_text(phy, 20))
        rate = row.get("transmit_rate")
        # Open security alone can describe an idle interface. Only review as open
        # when the getters also report an active PHY and nonzero transmit rate.
        active = power is True and isinstance(phy, int) and phy > 0 and isinstance(rate, (int, float)) and rate > 0
        evidence = [{"source": source, "detail": "%s；電源=%s；安全類型=%s；無線協定=%s；目前傳輸率指標=%s" %
                     (interface, "開啟" if power is True else "關閉" if power is False else "未知", security, protocol,
                      "非零" if active else "未能確認有效連線")}]
        status, severity, summary, actions = "unknown", "info", "目前連線的保護狀態無法判定。", []
        if power is False:
            status, summary = "not_checked", "Wi-Fi 目前關閉；沒有可評估的 Wi-Fi 連線。"
        elif not active:
            summary = "Wi-Fi 已開啟，但這次快照不足以確認有效連線或其保護狀態。"
        elif sec in (0, 1, 2, 3, 6, 7, 8):
            status, severity, summary = "attention", "medium", "目前介面回報 %s；建議確認是否可改用較新的加密方式。" % security
            actions = ["向網路管理者確認這是你預期使用的網路。", "路由器由你管理時，評估 WPA3 或 WPA2/WPA3；舊裝置相容性需一併確認。"]
        elif sec in (4, 9, 11, 12, 13):
            status, summary = "pass", "目前介面回報 %s，已辨識到 WPA2／WPA3 類型的連線保護。" % security
            actions = ["定期更新路由器韌體；使用公共網路時仍核對網址與網站的 HTTPS。"]
        elif sec in (14, 15):
            status, severity, summary = "review", "low", "目前回報 %s；無線傳輸可能加密，但仍需確認基地台身分。" % security
            actions = ["向場地或網路管理者核對正確網路；不要只憑名稱或有加密就信任。"]
        checks.append(check("network.wifi.%s" % i, "network", "Wi-Fi 連線保護 · %s" % interface, status, summary,
                            evidence, actions, severity, "Wi-Fi 加密保護裝置與基地台之間的無線傳輸。", limits, ["wifi_security", "https"]))
        devices.append({"name": "Wi-Fi · %s" % interface, "type": "Wi-Fi", "state": summary})
    if not checks:
        checks.append(check("network.wifi", "network", "Wi-Fi 連線保護", "unknown", "回傳資料格式不完整。", [], limitations=limits))
    return checks, devices


def bluetooth_checks(query=None):
    result = query if query is not None else run_json(["/usr/sbin/system_profiler", "SPBluetoothDataType", "-json"], 25)
    source = "system_profiler SPBluetoothDataType（僅保留允許的狀態／名稱）"
    limits = ["只保留控制器電源、可被探索狀態、已連線裝置名稱與未連線條目數；位址、序號與原始 JSON 不寫入報告。",
              "未探索附近裝置、發起配對或測試漏洞；目前連線與已記錄裝置不等於經常使用或可信任。"]
    data = result.get("data", {})
    rows = data.get("SPBluetoothDataType") if isinstance(data, dict) else None
    if result.get("status") != "ok" or not isinstance(rows, list) or not rows:
        return [check("devices.bluetooth", "devices", "藍牙與連線裝置", "unknown", "無法取得藍牙控制器與連線裝置狀態。",
                      [{"source": source, "detail": "查詢失敗、無控制器或格式不支援。"}],
                      ["在系統設定 → 藍牙核對目前裝置。"], limitations=limits, terms=["bluetooth"])], []
    checks, devices = [], []
    for i, row in enumerate(rows[:8]):
        if not isinstance(row, dict):
            continue
        props = row.get("controller_properties", {})
        if not isinstance(props, dict):
            props = {}
        power = props.get("controller_state")
        discoverable = props.get("controller_discoverable")
        connected = row.get("device_connected", [])
        known = row.get("device_not_connected", [])
        state_known = power in ("attrib_on", "attrib_off")
        count_known = ("device_connected" in row and "device_not_connected" in row
                       and isinstance(connected, list) and isinstance(known, list))
        connected = connected if isinstance(connected, list) else []
        known = known if isinstance(known, list) else []
        for entry in connected[:100]:
            if not isinstance(entry, dict):
                continue
            for name, properties in list(entry.items())[:10]:
                label = safe_text(name) or "未命名藍牙裝置"
                # Some OS versions use addresses as labels; never retain those.
                if re.search(r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}", label, re.I):
                    label = "未命名藍牙裝置"
                devices.append({"name": label, "type": "Bluetooth", "state": "目前已連線"})
        state = "開啟" if power == "attrib_on" else "關閉" if power == "attrib_off" else "未知"
        discover = "是" if discoverable == "attrib_on" else "否" if discoverable == "attrib_off" else "未知"
        status = "review" if state_known and count_known else "unknown"
        summary = "藍牙電源%s；本次看見 %s 個連線條目。請核對裝置是否認得。" % (state, len(connected)) if count_known else "藍牙電源%s；裝置清單格式無法判定。" % state
        if power == "attrib_off" and count_known and not connected:
            status, summary = "pass", "藍牙目前關閉，查詢未列出連線裝置。"
        checks.append(check("devices.bluetooth.%s" % i, "devices", "藍牙與連線裝置", status, summary,
                            [{"source": source, "detail": "電源=%s；可被探索=%s；已連線條目=%s；已記錄但未連線條目=%s" %
                              (state, discover, len(connected) if count_known else "未知", len(known) if count_known else "未知")}],
                            ["比對裝置清單；不認得的裝置先確認用途與擁有者，再決定是否解除配對。", "不使用藍牙時可自行評估關閉；本次沒有更改設定。"],
                            "info", "配對裝置可能使用音訊、鍵盤、滑鼠等功能；名稱本身不能證明裝置身分。", limits, ["bluetooth"]))
    return checks or [check("devices.bluetooth", "devices", "藍牙與連線裝置", "unknown", "藍牙資料格式不完整。", [], limitations=limits)], devices


def safe_regular_read(path, limit=512 * 1024):
    """Reject links, nonregular files, growth and replacement races before parsing metadata."""
    if path.is_symlink() or any(p.is_symlink() for p in path.absolute().parents):
        raise ValueError("symlink_not_read")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("not_bounded_regular_file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("file_changed")
        data = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
    if len(data) > limit or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError("file_changed_or_size_limit")
    return data


def applications(home, running_query=None, roots=None):
    result = running_query if running_query is not None else run_json(["/usr/bin/osascript", "-l", "JavaScript", "-e", RUNNING_SCRIPT])
    running_ok = result.get("status") == "ok" and isinstance(result.get("data"), list)
    running = [r for r in result.get("data", []) if isinstance(r, dict)] if running_ok else []
    by_id = {safe_text(r.get("bundle_id"), 200): r for r in running if r.get("bundle_id")}
    rows, coverage, seen = [], [], set()
    roots = roots or [(Path("/Applications"), "/Applications"), (Path("/System/Applications"), "/System/Applications"),
                     (home / "Applications", "~/Applications")]
    for root, label in roots:
        try:
            if root.is_symlink() or any(p.is_symlink() for p in root.absolute().parents):
                coverage.append({"source": label, "status": "skipped_symlink"})
                continue
            entries = list(itertools.islice(root.iterdir(), MAX_APPS + 1))
            candidates = [p for p in entries[:MAX_APPS] if p.suffix.lower() == ".app"]
            unreadable = skipped = 0
            for app in candidates:
                if len(rows) >= MAX_APPS:
                    skipped += 1
                    continue
                try:
                    info = plistlib.loads(safe_regular_read(app / "Contents/Info.plist"))
                    if not isinstance(info, dict):
                        raise ValueError("invalid_metadata")
                    identifier = safe_text(info.get("CFBundleIdentifier"), 200)
                    name = safe_text(info.get("CFBundleDisplayName") or info.get("CFBundleName") or app.stem)
                    version = safe_text(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion"), 64) or "未知"
                    active = identifier in by_id if identifier else False
                    if active:
                        seen.add(identifier)
                    rows.append({"name": name, "version": version, "source": label,
                                 "state": "目前執行（有介面）" if active else "本次未見有介面執行" if running_ok else "目前執行狀態未知"})
                except (OSError, ValueError, plistlib.InvalidFileException, OverflowError, ExpatError):
                    unreadable += 1
            coverage.append({"source": label, "status": "partial" if len(entries) > MAX_APPS or unreadable or skipped else "complete",
                             "application_candidates": len(candidates), "unreadable_or_skipped": unreadable + skipped})
        except FileNotFoundError:
            coverage.append({"source": label, "status": "absent"})
        except OSError as error:
            coverage.append({"source": label, "status": "unavailable", "reason": type(error).__name__})
    for identifier, row in by_id.items():
        if identifier not in seen and len(rows) < MAX_APPS + 100:
            rows.append({"name": safe_text(row.get("name")) or "未命名程式", "version": "未知",
                         "source": "NSWorkspace（未在上述目錄中對應）", "state": "目前執行（有介面）"})
    rows.sort(key=lambda r: (0 if r["state"] == "目前執行（有介面）" else 1, r["name"].casefold()))
    partial = not running_ok or any(x["status"] not in ("complete", "absent") for x in coverage)
    checks = [check("apps.inventory", "apps", "已安裝與目前執行的程式", "review" if rows else "unknown",
                    "取得 %s 筆程式資料；這是盤點快照，並非使用頻率或安全認證。" % len(rows),
                    [{"source": "App bundle Info.plist（僅名稱與版本）／NSWorkspace.runningApplications", "detail":
                      "已列出 %s 個有介面執行的程式；目錄覆蓋%s。" % (len(running), "部分未完成" if partial else "完成限定範圍") if running_ok
                      else "執行中程式查詢未完成；不得視為沒有程式執行。"}],
                    ["優先檢查常用程式的更新與高權限授權，並確認來源。", "不需要的程式先確認用途及相依性，再由你決定是否移除。"],
                    limitations=["最多掃描 300 個頂層 App；不展開全部子資料夾、不開啟程式或私人文件。", "只列 NSWorkspace 的一般有介面程式；背景服務、便攜程式、商店更新狀態及完整權限未在此模組驗證。", "未讀取使用歷史；目前執行不等於常用，未執行不等於不常用。"], terms=["app_permissions"])]
    return checks, rows, coverage


def collect(home):
    if platform.system() != "Darwin":
        return {"status": "unsupported", "reason": "The connectivity supplement supports macOS only."}
    wifi, wifi_devices = wifi_checks()
    bluetooth, bt_devices = bluetooth_checks()
    app_checks, apps, app_coverage = applications(home)
    checks = wifi + bluetooth + app_checks
    partial = any(c["status"] in ("unknown", "not_checked") for c in checks) or any(c["status"] not in ("complete", "absent") for c in app_coverage)
    return {"schema_version": "2.0", "platform": "Darwin", "module": "connectivity",
            "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(), "coverage_status": "partial" if partial else "complete",
            "checks": checks, "inventories": {"apps": apps, "devices": wifi_devices + bt_devices}, "app_coverage": app_coverage,
            "limitations": ["一次性唯讀快照；未啟動監控。", "使用頻率需另提供有明確來源與期間的聚合統計；沒有資料時顯示未知。", "僅寫入新報告；作業系統的正常查詢快取或日誌可能更新。"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path.home())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = collect(args.home.expanduser().absolute())
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    print(json.dumps({"status": report.get("status", "completed"), "coverage_status": report.get("coverage_status")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
