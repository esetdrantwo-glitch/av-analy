# -*- coding: utf-8 -*-
"""
report.py
تولید گزارش HTML قابل چاپ/اشتراک‌گذاری از نتیجه تحلیل.
بدون وابستگی خارجی — فقط رشته‌سازی HTML/CSS ساده.
"""

import html
import os
from datetime import datetime

SEVERITY_COLORS = {
    "Critical": "#c0392b", "High": "#e67e22", "Medium": "#f1c40f",
    "Low": "#2ecc71", "Info": "#95a5a6", "Unknown": "#7f8c8d",
}


def _esc(v):
    return html.escape(str(v)) if v is not None else ""


def _bar_rows(data, colors=None):
    if not data:
        return "<p>داده‌ای موجود نیست.</p>"
    max_val = max(v for _, v in data) or 1
    rows = []
    for label, val in data:
        pct = int((val / max_val) * 100)
        color = (colors or {}).get(label, "#3498db")
        rows.append(f"""
        <div class="bar-row">
          <div class="bar-label">{_esc(label)}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color};"></div></div>
          <div class="bar-value">{val}</div>
        </div>""")
    return "\n".join(rows)


def build_html_report(result, source_files=None):
    s = result["summary"]
    events = result["events"]
    high_priority = result["high_priority"]
    verdict, verdict_desc = s["verdict"]
    verdict_color = {"بحرانی": "#c0392b", "نیازمند توجه": "#e67e22",
                      "عادی": "#27ae60", "بدون داده": "#7f8c8d"}.get(verdict, "#333")

    sev_order = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
    sev_data = [(k, s["severity_counts"].get(k, 0)) for k in sev_order if s["severity_counts"].get(k, 0) > 0]
    top_threats_data = list(s["top_threats"][:10])
    tactic_data = sorted(s["tactic_counts"].items(), key=lambda x: -x[1])
    host_data = list(s["hosts_affected"][:10])

    files_html = ""
    if source_files:
        items = "".join(f"<li>{_esc(os.path.basename(p))}</li>" for p in source_files)
        files_html = f"<h3>فایل‌های منبع</h3><ul>{items}</ul>"

    rows_html = []
    for ev in events:
        ts = ev.get("timestamp")
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else _esc(ts)
        sev = ev.get("severity", "Unknown")
        color = SEVERITY_COLORS.get(sev, "#ccc")
        mitre = ev.get("mitre")
        mitre_str = _esc(mitre[1]) if mitre else "—"
        rows_html.append(f"""
        <tr>
          <td>{ts_str}</td>
          <td><span class="badge" style="background:{color}">{_esc(sev)}</span></td>
          <td>{_esc(ev.get('source'))}</td>
          <td>{_esc(ev.get('threat_name'))}</td>
          <td>{_esc(ev.get('action') or '—')}</td>
          <td>{_esc(ev.get('host') or '—')}</td>
          <td>{mitre_str}</td>
          <td>{ev.get('risk_score', 0)}</td>
        </tr>""")

    hp_html = []
    if not high_priority:
        hp_html.append("<p>موردی با اولویت بالا یافت نشد.</p>")
    for i, ev in enumerate(high_priority, 1):
        exp = _esc(ev["explanation"]).replace("\n", "<br>")
        recs = "".join(f"<li>{_esc(r)}</li>" for r in ev.get("recommendations", []))
        hp_html.append(f"""
        <div class="case">
          <h4>{i}. [{_esc(ev.get('severity'))}] {_esc(ev.get('threat_name'))}
              <span class="score">امتیاز ریسک: {ev.get('risk_score')}</span></h4>
          <p>{exp}</p>
          <strong>پیشنهاد اقدام:</strong>
          <ul>{recs}</ul>
        </div>""")

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<title>گزارش تحلیل لاگ آنتی‌ویروس/EDR</title>
<style>
  body {{ font-family: Tahoma, "Segoe UI", sans-serif; background:#f4f6f8; color:#222; margin:0; padding:0; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  header {{ background:#1f2a38; color:#fff; padding:24px; }}
  header h1 {{ margin:0 0 6px 0; font-size:22px; }}
  header .meta {{ color:#b7c2ce; font-size:13px; }}
  .verdict {{ display:inline-block; margin-top:10px; padding:8px 16px; border-radius:6px;
              font-weight:bold; color:#fff; background:{verdict_color}; }}
  .card {{ background:#fff; border-radius:8px; box-shadow:0 1px 4px rgba(0,0,0,0.08);
           padding:18px 22px; margin:18px 0; }}
  h2 {{ border-bottom:2px solid #eee; padding-bottom:8px; font-size:17px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ padding:8px 10px; border-bottom:1px solid #eee; text-align:right; }}
  th {{ background:#f0f2f5; }}
  tr:hover {{ background:#fafbfc; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:11px; }}
  .bar-row {{ display:flex; align-items:center; gap:10px; margin:6px 0; }}
  .bar-label {{ width:220px; font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .bar-track {{ flex:1; background:#eee; border-radius:4px; height:14px; overflow:hidden; }}
  .bar-fill {{ height:100%; }}
  .bar-value {{ width:36px; font-size:12px; text-align:left; }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
  .case {{ border-right:4px solid #c0392b; background:#fafafa; padding:12px 16px; margin:12px 0; border-radius:4px; }}
  .case h4 {{ margin:0 0 8px 0; }}
  .score {{ float:left; font-size:12px; color:#666; }}
  footer {{ text-align:center; color:#888; font-size:12px; padding:20px; }}
  .note {{ font-size:12px; color:#777; }}
  @media (max-width: 800px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>گزارش تحلیل لاگ آنتی‌ویروس / EDR</h1>
    <div class="meta">تاریخ تولید گزارش: {generated_at} — مجموع رویدادها: {s['total']}</div>
    <div class="verdict">وضعیت کلی: {_esc(verdict)}</div>
    <p style="margin-top:10px;">{_esc(verdict_desc)}</p>
  </div>
</header>

<div class="container">

  <div class="card">
    {files_html}
  </div>

  <div class="card grid2">
    <div>
      <h2>توزیع شدت رویدادها</h2>
      {_bar_rows(sev_data, SEVERITY_COLORS)}
    </div>
    <div>
      <h2>پرتکرارترین تهدیدها</h2>
      {_bar_rows(top_threats_data)}
    </div>
  </div>

  <div class="card grid2">
    <div>
      <h2>تاکتیک‌های MITRE ATT&amp;CK مشاهده‌شده (حدسی)</h2>
      {_bar_rows(tactic_data)}
      <p class="note">* تطبیق بر اساس کلیدواژه است، نه تحلیل قطعی؛ برای تایید نهایی به بررسی تخصصی نیاز است.</p>
    </div>
    <div>
      <h2>میزبان‌های درگیر</h2>
      {_bar_rows(host_data)}
    </div>
  </div>

  <div class="card">
    <h2>موارد پراولویت برای بررسی فوری ({len(high_priority)})</h2>
    {''.join(hp_html)}
  </div>

  <div class="card">
    <h2>جدول کامل رویدادها ({len(events)})</h2>
    <table>
      <thead>
        <tr><th>زمان</th><th>شدت</th><th>منبع</th><th>نام تهدید</th><th>اقدام</th>
            <th>میزبان</th><th>تکنیک MITRE</th><th>امتیاز ریسک</th></tr>
      </thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>
  </div>

</div>
<footer>تولید شده توسط تحلیل‌گر لاگ آنتی‌ویروس/EDR — این گزارش جایگزین بررسی توسط کارشناس امنیت نیست.</footer>
</body>
</html>"""
