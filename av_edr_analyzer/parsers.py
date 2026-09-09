# -*- coding: utf-8 -*-
"""
parsers.py
ماژول تشخیص فرمت و استخراج رویدادها از لاگ‌های آنتی‌ویروس/EDR

پشتیبانی از:
  - Windows Defender (خروجی PowerShell Get-MpThreatDetection به CSV/JSON، یا Export رویداد ویندوز به CSV)
  - CrowdStrike Falcon (CSV/JSON دیتکشن‌ها)
  - SentinelOne (CSV/JSON تهدیدها)
  - VMware Carbon Black (JSON alerts)
  - فایل‌های عمومی CSV / JSON / متنی با تشخیص هوشمند ستون‌ها

خروجی همه‌ی پارسرها یک ساختار یکسان (Normalized Event) است تا لایه تحلیل
مستقل از منبع لاگ کار کند.
"""

import csv
import json
import re
import os
from datetime import datetime

# ---------------------------------------------------------------------------
# ساختار استاندارد یک رویداد پس از نرمال‌سازی
# ---------------------------------------------------------------------------
EVENT_FIELDS = [
    "timestamp", "source", "severity", "threat_name", "action",
    "file_path", "process", "cmdline", "user", "host", "hash", "raw"
]


def empty_event():
    return {k: "" for k in EVENT_FIELDS}


# ---------------------------------------------------------------------------
# نگاشت نام ستون‌ها برای هر محصول شناخته‌شده (case-insensitive)
# ---------------------------------------------------------------------------
COLUMN_MAPS = {
    "windows_defender": {
        "timestamp": ["initialdetectiontime", "detectiontime", "date", "time", "timecreated"],
        "severity": ["severityid", "severity", "level"],
        "threat_name": ["threatname", "threat", "name", "message"],
        "action": ["actionsuccess", "action", "resources"],
        "file_path": ["resources", "path", "filename"],
        "process": ["processname", "process"],
        "user": ["domainuser", "user", "username"],
        "host": ["computername", "host", "device"],
        "hash": ["sha256", "sha1", "md5"],
    },
    "crowdstrike": {
        "timestamp": ["timestamp", "detect_time", "created_timestamp", "date"],
        "severity": ["severity", "severity_name", "max_severity_displayname"],
        "threat_name": ["detect_name", "display_name", "technique", "tactic"],
        "action": ["status", "action_taken", "product_status"],
        "file_path": ["filepath", "filename", "file_name"],
        "process": ["process_name", "parent_process_name", "image_file_name"],
        "cmdline": ["cmdline", "commandline", "parent_cmdline"],
        "user": ["user_name", "username"],
        "host": ["hostname", "device_name", "sensor_id"],
        "hash": ["sha256", "sha256_hash", "md5", "md5_hash"],
    },
    "sentinelone": {
        "timestamp": ["threat_created_at", "createdat", "detection_time", "time"],
        "severity": ["threat_classification", "confidencelevel", "severity"],
        "threat_name": ["threat_name", "threatname", "classification"],
        "action": ["mitigation_status", "mitigationstatus", "incident_status"],
        "file_path": ["file_path", "filepath", "originalfilename"],
        "process": ["process_name", "processname"],
        "cmdline": ["process_cmd", "cmdline"],
        "user": ["username", "user"],
        "host": ["endpoint_name", "computername", "agent_computer_name"],
        "hash": ["file_sha256", "sha256", "file_sha1", "sha1", "file_md5", "md5"],
    },
    "carbonblack": {
        "timestamp": ["create_time", "event_timestamp", "timestamp"],
        "severity": ["severity", "risk_score"],
        "threat_name": ["reason", "threat_indicators", "ioc_hit", "alert_type"],
        "action": ["status", "workflow", "policy_action"],
        "file_path": ["path", "filepath", "device_path"],
        "process": ["process_name", "process_path"],
        "cmdline": ["cmdline", "process_cmdline"],
        "user": ["device_username", "user"],
        "host": ["device_name", "host"],
        "hash": ["sha256", "process_sha256", "md5"],
    },
}

# کلید و مقادیر عمومی برای پارسر fallback (وقتی محصول شناسایی نشود)
GENERIC_KEYS = {
    "timestamp": ["timestamp", "time", "date", "datetime", "created", "detected", "occurred"],
    "severity": ["severity", "risk", "level", "priority", "classification"],
    "threat_name": ["threat", "malware", "name", "signature", "detection", "alert", "rule", "message", "title"],
    "action": ["action", "status", "mitigation", "response", "result", "disposition"],
    "file_path": ["path", "file", "filepath", "filename", "object"],
    "process": ["process", "image", "processname", "application"],
    "cmdline": ["cmdline", "commandline", "command"],
    "user": ["user", "username", "account"],
    "host": ["host", "hostname", "computer", "device", "endpoint", "machine"],
    "hash": ["hash", "sha256", "sha1", "md5"],
}

# --------------------------------------------------------------------
# کلیدواژه‌های سطح‌بندی شدت (وقتی مقدار severity عددی/متنیِ ناآشنا باشد)
# --------------------------------------------------------------------
SEVERITY_NORMALIZE = {
    "critical": "Critical", "high": "High", "severe": "Critical",
    "medium": "Medium", "moderate": "Medium", "low": "Low",
    "informational": "Info", "info": "Info", "clean": "Info",
    "4": "Critical", "3": "High", "2": "Medium", "1": "Low", "0": "Info",
    "5": "Critical",
    "suspicious": "Medium", "malicious": "Critical", "pup": "Low",
}


def normalize_severity(value):
    if value is None:
        return "Unknown"
    v = str(value).strip().lower()
    if v in SEVERITY_NORMALIZE:
        return SEVERITY_NORMALIZE[v]
    for key, norm in SEVERITY_NORMALIZE.items():
        if key in v:
            return norm
    return "Unknown" if not v else value.strip().title()


def parse_timestamp(value):
    """تلاش برای تبدیل رشته‌های مختلف زمان به datetime؛ در صورت شکست رشته اصلی برگردانده می‌شود."""
    if not value:
        return None
    value = str(value).strip()
    fmts = [
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S",
        "%b %d, %Y %I:%M:%S %p", "%Y-%m-%d",
    ]
    for f in fmts:
        try:
            return datetime.strptime(value, f)
        except ValueError:
            continue
    # تلاش برای epoch (ثانیه یا میلی‌ثانیه)
    try:
        num = float(value)
        if num > 10 ** 12:
            num /= 1000.0
        return datetime.fromtimestamp(num)
    except (ValueError, OSError, OverflowError):
        return None


def _lower_keys(d):
    return {str(k).strip().lower(): v for k, v in d.items()}


def _map_row(row, colmap, source_label):
    """یک ردیف (dict) را با استفاده از نگاشت ستون به رویداد نرمال تبدیل می‌کند."""
    lrow = _lower_keys(row)
    ev = empty_event()
    ev["source"] = source_label
    for field, candidates in colmap.items():
        for c in candidates:
            if c in lrow and str(lrow[c]).strip():
                ev[field] = str(lrow[c]).strip()
                break
    ev["severity"] = normalize_severity(ev.get("severity") or "")
    ts = parse_timestamp(ev.get("timestamp"))
    ev["timestamp"] = ts if ts else ev.get("timestamp") or ""
    ev["raw"] = dict(row)
    if not ev["threat_name"]:
        ev["threat_name"] = "نامشخص"
    return ev


# ---------------------------------------------------------------------------
# تشخیص فرمت فایل
# ---------------------------------------------------------------------------
def sniff_format(path):
    """
    فرمت و 'محصول' فایل را حدس می‌زند.
    خروجی: tuple(filetype, product) با filetype در {csv, json, text}
    """
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            head = f.read(4096)
    except OSError:
        return "text", "generic"

    stripped = head.strip()
    filetype = "text"
    if ext == ".json" or stripped.startswith("{") or stripped.startswith("["):
        filetype = "json"
    elif ext in (".csv", ".tsv") or ("," in head.splitlines()[0] if head.splitlines() else False):
        filetype = "csv"

    lower_head = head.lower()
    product = "generic"
    if "crowdstrike" in lower_head or "falcon" in lower_head or "detect_id" in lower_head:
        product = "crowdstrike"
    elif "sentinelone" in lower_head or "mitigation_status" in lower_head or "threat_classification" in lower_head:
        product = "sentinelone"
    elif "carbonblack" in lower_head or "carbon black" in lower_head or "cb_" in lower_head:
        product = "carbonblack"
    elif "windows defender" in lower_head or "microsoft-windows-windows defender" in lower_head \
            or "mpthreatdetection" in lower_head or "threatname" in lower_head:
        product = "windows_defender"

    return filetype, product


# ---------------------------------------------------------------------------
# پارسرهای CSV / JSON
# ---------------------------------------------------------------------------
def parse_csv(path, product):
    events = []
    colmap = COLUMN_MAPS.get(product, GENERIC_KEYS)
    label = PRODUCT_LABELS.get(product, "نامشخص (CSV عمومی)")
    with open(path, "r", encoding="utf-8-sig", errors="ignore", newline="") as f:
        sample = f.read(2048)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            if not row or all(not str(v).strip() for v in row.values()):
                continue
            events.append(_map_row(row, colmap, label))
    return events


def parse_json(path, product):
    events = []
    colmap = COLUMN_MAPS.get(product, GENERIC_KEYS)
    label = PRODUCT_LABELS.get(product, "نامشخص (JSON عمومی)")
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
        data = json.load(f)

    records = []
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        # الگوهای رایج: {"results":[...]}, {"data":[...]}, {"detections":[...]}, {"alerts":[...]}
        for key in ("results", "data", "detections", "alerts", "events", "resources", "threats"):
            if key in data and isinstance(data[key], list):
                records = data[key]
                break
        if not records:
            records = [data]

    for rec in records:
        if not isinstance(rec, dict):
            continue
        flat = _flatten(rec)
        events.append(_map_row(flat, colmap, label))
    return events


def _flatten(d, prefix=""):
    """یک سطح تخت‌سازی dict تودرتو برای پیدا کردن فیلدهای داخل آبجکت‌های تو در تو."""
    flat = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            flat.update(_flatten(v, prefix=f"{key}."))
            # نسخه بدون پیشوند هم برای تطبیق راحت‌تر ستون‌ها
            for kk, vv in v.items():
                flat.setdefault(kk, vv)
        elif isinstance(v, list):
            flat[key] = "; ".join(str(x) for x in v[:5])
        else:
            flat[key] = v
    return flat


# ---------------------------------------------------------------------------
# پارسر متنی عمومی (لاگ‌های خط به خط بدون ساختار جدولی)
# ---------------------------------------------------------------------------
TEXT_LINE_PATTERNS = [
    # 2024-05-01 12:30:00 [Critical] Threat: Trojan.Win32.X blocked on HOST01
    re.compile(
        r"(?P<timestamp>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2})"
        r".*?(?:\[(?P<severity>\w+)\])?"
        r".*?(?:threat|malware|detection)[:\s]+(?P<threat_name>[^,;|]+)",
        re.IGNORECASE,
    ),
]

KEYWORD_SEVERITY = [
    (re.compile(r"ransomware|critical|blocked malicious|c2|cobalt\s*strike", re.I), "Critical"),
    (re.compile(r"trojan|backdoor|rootkit|exploit|credential|mimikatz|lsass", re.I), "High"),
    (re.compile(r"suspicious|pup|adware|potentially unwanted|riskware", re.I), "Medium"),
    (re.compile(r"clean|allowed|informational|scan completed", re.I), "Info"),
]


def parse_text(path):
    events = []
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ev = empty_event()
            ev["source"] = "لاگ متنی عمومی"
            ev["raw"] = line
            matched = False
            for pat in TEXT_LINE_PATTERNS:
                m = pat.search(line)
                if m:
                    gd = m.groupdict()
                    ts = parse_timestamp(gd.get("timestamp"))
                    ev["timestamp"] = ts if ts else gd.get("timestamp") or ""
                    ev["severity"] = normalize_severity(gd.get("severity") or "")
                    ev["threat_name"] = (gd.get("threat_name") or "نامشخص").strip()
                    matched = True
                    break
            if not matched:
                # تلاش برای پیدا کردن timestamp مستقل در ابتدای خط
                ts_match = re.match(r"(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2})", line)
                ev["timestamp"] = parse_timestamp(ts_match.group(1)) if ts_match else ""
                ev["threat_name"] = line[:120]
            if ev["severity"] in ("", "Unknown"):
                sev = "Info"
                for pat, level in KEYWORD_SEVERITY:
                    if pat.search(line):
                        sev = level
                        break
                ev["severity"] = sev
            events.append(ev)
    return events


PRODUCT_LABELS = {
    "windows_defender": "Windows Defender",
    "crowdstrike": "CrowdStrike Falcon",
    "sentinelone": "SentinelOne",
    "carbonblack": "VMware Carbon Black",
    "generic": "منبع عمومی",
}


# ---------------------------------------------------------------------------
# ورودی اصلی ماژول
# ---------------------------------------------------------------------------
def parse_file(path):
    """
    فایل لاگ را پارس کرده و لیستی از رویدادهای نرمال‌شده برمی‌گرداند.
    همچنین متادیتای تشخیص (فرمت و محصول) را برمی‌گرداند.
    """
    filetype, product = sniff_format(path)
    try:
        if filetype == "csv":
            events = parse_csv(path, product)
        elif filetype == "json":
            events = parse_json(path, product)
        else:
            events = parse_text(path)
    except Exception as e:
        raise RuntimeError(f"خطا در پردازش فایل «{os.path.basename(path)}»: {e}")

    for ev in events:
        ev["_source_file"] = os.path.basename(path)

    return events, filetype, product
