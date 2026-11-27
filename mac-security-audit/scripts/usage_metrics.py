#!/usr/bin/env python3
"""Validate explicit, aggregate-only app/skill usage imports. Never read activity histories."""
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat


MAX_BYTES = 1024 * 1024
MAX_ITEMS = 1000
MAX_COUNT = 1_000_000_000


class UsageValidationError(ValueError):
    """Safe generic validation message; never includes submitted content."""


def unknown_usage(reason="沒有提供具來源及時間範圍的聚合使用統計。"):
    return {kind: {"status": "unknown", "source": reason, "period_start": None, "period_end": None,
                   "unit": "invocations" if kind == "skills" else "launches", "items": []}
            for kind in ("skills", "apps")}


def _label(value, field, limit):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise UsageValidationError("%s 必須是長度受限的名稱。" % field)
    if re.search(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]", value):
        raise UsageValidationError("名稱不可含控制字元。")
    # This interchange accepts labels, not URLs, paths, credentials or raw log text.
    if re.search(r"https?://|[/\\]|\b(?:sk-|ghp_|AKIA)[A-Za-z0-9_-]{8,}|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", value, re.I):
        raise UsageValidationError("僅允許簡短名稱；不可放網址、路徑、電子郵件或憑證。")
    if re.search(r"[A-Za-z0-9_=-]{80,}", value):
        raise UsageValidationError("名稱疑似含長識別碼；請只提供顯示名稱。")
    return value.strip()


def _time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise UsageValidationError("期間需為附時區的 ISO 8601 日期時間。")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise UsageValidationError("期間需為附時區的 ISO 8601 日期時間。")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise UsageValidationError("期間必須附時區，避免跨電腦誤判。")
    return parsed


def _reject_duplicates(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise UsageValidationError("JSON 不可有重複欄位。")
        output[key] = value
    return output


def normalize_usage(data, now=None):
    if not isinstance(data, dict) or set(data) - {"schema_version", "source", "period_start", "period_end", "skills", "apps"}:
        raise UsageValidationError("只接受指定的聚合統計欄位；不可加入事件內容或私人紀錄。")
    if data.get("schema_version") != 1 or isinstance(data.get("schema_version"), bool):
        raise UsageValidationError("usage schema_version 必須為 1。")
    source = _label(data.get("source"), "source", 160)
    start, end = _time(data.get("period_start")), _time(data.get("period_end"))
    now = now or dt.datetime.now(dt.timezone.utc)
    if start >= end or end > now + dt.timedelta(minutes=5):
        raise UsageValidationError("期間需依先後順序且不可晚於目前時間。")
    if not any(key in data for key in ("skills", "apps")):
        raise UsageValidationError("至少提供 skills 或 apps 的聚合清單。")
    result = unknown_usage("匯入資料未包含此類別。")
    for kind in ("skills", "apps"):
        if kind not in data:
            continue
        rows = data[kind]
        if not isinstance(rows, list) or len(rows) > MAX_ITEMS:
            raise UsageValidationError("每類使用統計需為最多 1000 筆的清單。")
        items, seen = [], set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"name", "count"}:
                raise UsageValidationError("每筆僅能包含 name 和 count。")
            name = _label(row["name"], "name", 120)
            count = row["count"]
            if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= MAX_COUNT:
                raise UsageValidationError("使用次數需為 0 至 1000000000 的整數。")
            if name.casefold() in seen:
                raise UsageValidationError("同類名稱不可重複；請先彙總。")
            seen.add(name.casefold())
            items.append({"name": name, "count": count})
        items.sort(key=lambda x: (-x["count"], x["name"].casefold()))
        result[kind] = {"status": "available", "source": source, "period_start": start.isoformat(), "period_end": end.isoformat(),
                        "unit": "invocations" if kind == "skills" else "launches", "items": items,
                        "limitation": "使用者提供的聚合資料；未核驗原始事件。只涵蓋提供的名稱，缺席名稱的使用率未知；次數不代表時數或不安全。"}
    return result


def load_usage(path=None):
    if path is None:
        return unknown_usage()
    path = Path(path).expanduser().absolute()
    try:
        if path.is_symlink() or any(p.is_symlink() for p in path.parents):
            raise UsageValidationError("使用統計檔案及其上層不可為符號連結。")
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
            raise UsageValidationError("使用統計需為最多 1 MiB 的一般 JSON 檔案。")
        # On Windows also reject reparse points (junctions are not always symlinks).
        for p in (path,) + tuple(path.parents):
            if getattr(p.lstat(), "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                raise UsageValidationError("使用統計路徑不可含 Windows reparse point。")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise UsageValidationError("使用統計檔案已變更，未匯入。")
            raw = handle.read(MAX_BYTES + 1)
            after = os.fstat(handle.fileno())
        if len(raw) > MAX_BYTES or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise UsageValidationError("使用統計檔案超過上限或讀取途中已變更。")
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_reject_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(UsageValidationError("不可使用 NaN 或 Infinity。")))
        return normalize_usage(data)
    except UsageValidationError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise UsageValidationError("使用統計無法讀取或格式不正確；沒有匯入。")
