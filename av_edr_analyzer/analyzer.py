# -*- coding: utf-8 -*-
"""
analyzer.py
موتور تحلیل رویدادهای نرمال‌شده‌ی آنتی‌ویروس/EDR:
  - امتیازدهی ریسک به هر رویداد
  - تطبیق حدسی با تکنیک‌های MITRE ATT&CK بر اساس کلیدواژه‌ها
  - تولید توضیح فارسی برای هر رویداد (چه اتفاقی افتاده، چرا مهم است، چه باید کرد)
  - تهیه آمار کلی و اولویت‌بندی برای داشبورد
"""

import re
from collections import Counter, defaultdict
from datetime import datetime

SEVERITY_WEIGHT = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15, "Info": 2, "Unknown": 20}

# اکشن‌هایی که یعنی تهدید خنثی/مهار شده
CONTAINED_ACTIONS = re.compile(
    r"quarantine|block|kill|remove|clean|remediat|delete|deny", re.I
)
# اکشن‌هایی که یعنی تهدید هنوز فعال است / اقدامی نشده
UNCONTAINED_ACTIONS = re.compile(
    r"allow|not mitigated|not blocked|detected only|ignore|permit|pending|no action",
    re.I,
)

# نگاشت حدسی کلیدواژه -> (تاکتیک، تکنیک MITRE، توضیح کوتاه)
MITRE_HINTS = [
    (re.compile(r"mimikatz|lsass|sekurlsa|dump.*credential", re.I),
     ("Credential Access", "T1003 - OS Credential Dumping",
      "تلاش برای استخراج رمزهای عبور/هش از حافظه سیستم (اغلب lsass.exe)")),
    (re.compile(r"vssadmin.*delete|shadow.*copy.*delet|wbadmin delete", re.I),
     ("Impact", "T1490 - Inhibit System Recovery",
      "حذف Shadow Copy یا بکاپ‌ها، رفتار کلاسیک باج‌افزارها پیش از رمزنگاری فایل‌ها")),
    (re.compile(r"ransom|filecoder|lockbit|conti|encrypt.*files|\.locked\b", re.I),
     ("Impact", "T1486 - Data Encrypted for Impact",
      "نشانه‌های باج‌افزار (رمزنگاری فایل‌ها جهت اخاذی)")),
    (re.compile(r"powershell.*(-enc|-encodedcommand|iex|downloadstring|-nop\b)", re.I),
     ("Execution", "T1059.001 - PowerShell",
      "اجرای دستور PowerShell با کدگذاری/دانلود از راه دور، الگوی رایج بدافزارهای بدون فایل (fileless)")),
    (re.compile(r"rundll32|regsvr32|mshta|certutil.*-urlcache|bitsadmin", re.I),
     ("Defense Evasion", "T1218 - System Binary Proxy Execution",
      "سوءاستفاده از ابزارهای قانونی ویندوز (LOLBins) برای اجرای مخفیانه کد یا دانلود فایل")),
    (re.compile(r"cobalt\s*strike|beacon|c2|command.?and.?control", re.I),
     ("Command and Control", "T1071 - Application Layer Protocol",
      "ارتباط با زیرساخت فرمان‌و‌کنترل (C2) — احتمال نفوذ فعال و کنترل از راه دور مهاجم")),
    (re.compile(r"psexec|wmic\s|winrm|remote.*service|smb.*exec", re.I),
     ("Lateral Movement", "T1021/T1570 - Remote Services / Lateral Tool Transfer",
      "استفاده از ابزارهای اجرای از راه دور برای حرکت جانبی بین سیستم‌ها")),
    (re.compile(r"scheduled ?task|schtasks|at\.exe|cron", re.I),
     ("Persistence", "T1053 - Scheduled Task/Job",
      "ایجاد یا تغییر Scheduled Task جهت ماندگاری (Persistence) بدافزار")),
    (re.compile(r"run\\?key|hkcu\\.*run|hklm\\.*run|startup folder|registry.*persist", re.I),
     ("Persistence", "T1547.001 - Registry Run Keys / Startup Folder",
      "افزودن به کلیدهای اجرای خودکار ویندوز برای اجرا در هر بار بوت/لاگین")),
    (re.compile(r"phishing|malicious.*attachment|macro.*enabled|\.docm|\.xlsm", re.I),
     ("Initial Access", "T1566 - Phishing",
      "احتمال ورود اولیه از طریق ایمیل فیشینگ یا فایل آفیس آلوده به ماکرو")),
    (re.compile(r"trojan|backdoor|rat\b|remote access trojan", re.I),
     ("Execution / C2", "T1105 - Ingress Tool Transfer",
      "تروجان/بک‌دور که معمولاً امکان کنترل از راه دور یا دانلود ابزار اضافه را می‌دهد")),
    (re.compile(r"exploit|cve-\d{4}-\d+|buffer overflow|privilege escalation", re.I),
     ("Privilege Escalation", "T1068 - Exploitation for Privilege Escalation",
      "بهره‌برداری از آسیب‌پذیری نرم‌افزاری، احتمالاً برای افزایش سطح دسترسی")),
    (re.compile(r"pup|adware|toolbar|installcore|riskware", re.I),
     ("N/A", "—",
      "نرم‌افزار ناخواسته/تبلیغاتی (PUA) - ریسک امنیتی مستقیم پایین اما مزاحم و گاهی درِ ورود بدافزار دیگر")),
]


def score_event(ev):
    """امتیاز ریسک 0..100+ برای یک رویداد بر اساس شدت، وضعیت مهار و کلیدواژه‌های حساس."""
    score = SEVERITY_WEIGHT.get(ev.get("severity", "Unknown"), 20)
    action = str(ev.get("action", ""))
    haystack = " ".join(str(ev.get(k, "")) for k in
                         ("threat_name", "action", "cmdline", "process", "file_path"))

    if UNCONTAINED_ACTIONS.search(action) or UNCONTAINED_ACTIONS.search(haystack):
        score += 25
    elif CONTAINED_ACTIONS.search(action):
        score -= 15

    for pattern, _ in [(p, h) for p, h in MITRE_HINTS]:
        if pattern.search(haystack):
            score += 10
            break  # فقط یک بار جایزه تطبیق تکنیک اضافه شود

    return max(0, min(150, score))


def match_mitre(ev):
    haystack = " ".join(str(ev.get(k, "")) for k in
                         ("threat_name", "cmdline", "process", "file_path"))
    for pattern, info in MITRE_HINTS:
        if pattern.search(haystack):
            return info
    return None


def explain_event(ev):
    """یک توضیح کامل فارسی برای یک رویداد تولید می‌کند."""
    sev = ev.get("severity", "Unknown")
    name = ev.get("threat_name") or "نامشخص"
    action = ev.get("action") or "ثبت‌نشده"
    host = ev.get("host") or "نامشخص"
    proc = ev.get("process")
    path = ev.get("file_path")
    ts = ev.get("timestamp")
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else (str(ts) or "زمان نامشخص")

    mitre = match_mitre(ev)
    is_contained = bool(CONTAINED_ACTIONS.search(action)) and not UNCONTAINED_ACTIONS.search(action)

    lines = []
    lines.append(f"در تاریخ {ts_str} روی سیستم «{host}» یک رویداد با شدت «{sev}» ثبت شده است.")
    lines.append(f"عنوان تهدید: {name}")
    if proc:
        lines.append(f"پردازه درگیر: {proc}")
    if path:
        lines.append(f"مسیر فایل: {path}")
    lines.append(f"اقدام محصول امنیتی: {action or 'نامشخص'}")

    if mitre:
        tactic, technique, desc = mitre
        lines.append(f"تطبیق حدسی MITRE ATT&CK: {technique} (تاکتیک: {tactic}) — {desc}")

    if is_contained:
        lines.append("وضعیت: تهدید ظاهراً توسط محصول امنیتی مهار/حذف شده است، اما توصیه می‌شود از پاکسازی کامل سیستم اطمینان حاصل شود.")
    elif UNCONTAINED_ACTIONS.search(action) or not action:
        lines.append("⚠️ وضعیت: تهدید مهار نشده یا وضعیت آن نامشخص است — این مورد نیاز به بررسی فوری تیم امنیتی دارد.")
    else:
        lines.append("وضعیت: نیازمند بررسی دستی برای تعیین اینکه آیا اقدام کافی صورت گرفته یا خیر.")

    return "\n".join(lines)


def recommend_for_event(ev, mitre):
    """پیشنهاد اقدام کوتاه بر اساس نوع تهدید."""
    action = str(ev.get("action", ""))
    recs = []
    if UNCONTAINED_ACTIONS.search(action) or not action:
        recs.append(f"ایزوله کردن فوری سیستم «{ev.get('host') or 'مربوطه'}» از شبکه تا بررسی کامل.")
    if mitre:
        tactic = mitre[0]
        if tactic == "Credential Access":
            recs.append("ریست فوری رمزهای عبور حساب‌های درگیر و بررسی فعالیت‌های ورود مشکوک (Lateral Movement).")
        elif tactic == "Impact":
            recs.append("بررسی وضعیت بکاپ‌ها و Shadow Copy؛ در صورت رمزنگاری فایل‌ها، فعال‌سازی پلن واکنش به باج‌افزار.")
        elif tactic == "Command and Control":
            recs.append("بلاک کردن IP/دامنه C2 در فایروال و بررسی سایر میزبان‌ها برای همان IOC.")
        elif tactic == "Lateral Movement":
            recs.append("بررسی لاگ‌های احراز هویت برای سایر سیستم‌هایی که همین حساب/ابزار به آن‌ها متصل شده.")
        elif tactic == "Persistence":
            recs.append("بررسی و حذف مکانیزم Persistence (Scheduled Task/Registry Run Key) و اسکن کامل سیستم.")
        elif tactic == "Initial Access":
            recs.append("آموزش کاربر مربوطه و بررسی ایمیل/فایل ورودی برای شناسایی سایر گیرندگان احتمالی.")
    if ev.get("hash"):
        recs.append(f"جست‌وجوی هش {ev.get('hash')[:16]}... در VirusTotal/Threat Intel برای تایید سوءقصد.")
    if not recs:
        recs.append("بررسی دوره‌ای کافی است؛ در حال حاضر نشانه بحرانی مشاهده نمی‌شود.")
    return recs


def analyze(events):
    """
    تحلیل کامل روی لیست رویدادهای نرمال‌شده.
    خروجی dict شامل: events غنی‌شده، آمار خلاصه، و رتبه‌بندی اولویت.
    """
    enriched = []
    for ev in events:
        e = dict(ev)
        e["risk_score"] = score_event(ev)
        e["mitre"] = match_mitre(ev)
        e["explanation"] = explain_event(ev)
        e["recommendations"] = recommend_for_event(ev, e["mitre"])
        enriched.append(e)

    enriched.sort(key=lambda x: x["risk_score"], reverse=True)

    total = len(enriched)
    sev_counts = Counter(e.get("severity", "Unknown") for e in enriched)
    source_counts = Counter(e.get("source", "نامشخص") for e in enriched)
    action_status = Counter(
        "مهار شده" if CONTAINED_ACTIONS.search(str(e.get("action", ""))) and
        not UNCONTAINED_ACTIONS.search(str(e.get("action", "")))
        else ("مهار نشده" if UNCONTAINED_ACTIONS.search(str(e.get("action", ""))) else "نامشخص")
        for e in enriched
    )
    top_threats = Counter(e.get("threat_name", "نامشخص") for e in enriched).most_common(10)
    hosts_affected = Counter(e.get("host", "نامشخص") for e in enriched if e.get("host")).most_common(10)

    tactic_counts = Counter()
    for e in enriched:
        if e["mitre"]:
            tactic_counts[e["mitre"][0]] += 1

    by_day = defaultdict(int)
    for e in enriched:
        ts = e.get("timestamp")
        if isinstance(ts, datetime):
            by_day[ts.strftime("%Y-%m-%d")] += 1
    timeline = sorted(by_day.items())

    high_priority = [e for e in enriched if e["risk_score"] >= 70][:25]

    if sev_counts.get("Critical", 0) > 0 and action_status.get("مهار نشده", 0) > 0:
        verdict = ("بحرانی", "حداقل یک تهدید بحرانی مهارنشده شناسایی شد. رسیدگی فوری تیم امنیتی لازم است.")
    elif sev_counts.get("Critical", 0) > 0 or sev_counts.get("High", 0) > 2:
        verdict = ("نیازمند توجه", "موارد پرخطر مشاهده شد؛ اکثراً مهار شده‌اند ولی بررسی تکمیلی توصیه می‌شود.")
    elif total == 0:
        verdict = ("بدون داده", "هیچ رویدادی برای تحلیل یافت نشد.")
    else:
        verdict = ("عادی", "رویدادهای ثبت‌شده عمدتاً کم‌خطر یا مهار شده هستند.")

    summary = {
        "total": total,
        "severity_counts": dict(sev_counts),
        "source_counts": dict(source_counts),
        "action_status": dict(action_status),
        "top_threats": top_threats,
        "hosts_affected": hosts_affected,
        "tactic_counts": dict(tactic_counts),
        "timeline": timeline,
        "verdict": verdict,
    }

    return {
        "events": enriched,
        "summary": summary,
        "high_priority": high_priority,
    }
