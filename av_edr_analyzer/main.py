# -*- coding: utf-8 -*-
"""
main.py
تحلیل‌گر لاگ آنتی‌ویروس / EDR — رابط گرافیکی دسکتاپ (Tkinter)

اجرا:
    python main.py

بستن به فایل اجرایی ویندوز (.exe):
    pip install pyinstaller
    pyinstaller --onefile --windowed --name AV-EDR-Analyzer main.py
"""

import os
import sys
import traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

from parsers import parse_file, PRODUCT_LABELS
from analyzer import analyze
from report import build_html_report

APP_TITLE = "تحلیل‌گر لاگ آنتی‌ویروس / EDR"
FONT_NAME = "Tahoma"  # فونتی که از حروف فارسی/عربی به‌خوبی روی ویندوز پشتیبانی می‌کند

SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#2ecc71",
    "Info": "#95a5a6",
    "Unknown": "#7f8c8d",
}


def fa(text):
    """کمکی برای برگرداندن متن (جای نگه‌دار برای بهبودهای آتی bidi در صورت نیاز)."""
    return text


class BarChart(tk.Canvas):
    """نمودار میله‌ای ساده بدون وابستگی خارجی (بدون matplotlib)."""

    def __init__(self, master, width=520, height=220, **kw):
        super().__init__(master, width=width, height=height, bg="white",
                          highlightthickness=1, highlightbackground="#ddd", **kw)
        self._w = width
        self._h = height

    def draw(self, data, colors=None, title=""):
        """data: لیست (برچسب، مقدار)"""
        self.delete("all")
        if not data:
            self.create_text(self._w // 2, self._h // 2, text="داده‌ای برای نمایش نیست",
                              font=(FONT_NAME, 10))
            return
        pad_left, pad_bottom, pad_top, pad_right = 40, 50, 25, 15
        chart_w = self._w - pad_left - pad_right
        chart_h = self._h - pad_top - pad_bottom
        max_val = max(v for _, v in data) or 1
        n = len(data)
        bar_w = chart_w / n * 0.6
        gap = chart_w / n

        if title:
            self.create_text(self._w // 2, 12, text=title, font=(FONT_NAME, 10, "bold"))

        # محورها
        self.create_line(pad_left, pad_top, pad_left, pad_top + chart_h, fill="#999")
        self.create_line(pad_left, pad_top + chart_h, pad_left + chart_w, pad_top + chart_h, fill="#999")

        for i, (label, val) in enumerate(data):
            x0 = pad_left + i * gap + (gap - bar_w) / 2
            bar_h = (val / max_val) * chart_h
            y0 = pad_top + chart_h - bar_h
            y1 = pad_top + chart_h
            color = (colors or {}).get(label, "#3498db")
            self.create_rectangle(x0, y0, x0 + bar_w, y1, fill=color, outline="")
            self.create_text(x0 + bar_w / 2, y0 - 10, text=str(val), font=(FONT_NAME, 9))
            lbl = label if len(str(label)) <= 14 else str(label)[:13] + "…"
            self.create_text(x0 + bar_w / 2, pad_top + chart_h + 15, text=lbl,
                              font=(FONT_NAME, 8), angle=0)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x760")
        self.minsize(900, 600)

        self.loaded_files = []       # مسیر فایل‌های بارگذاری‌شده
        self.raw_events = []         # رویدادهای خام پارس‌شده (قبل از تحلیل)
        self.result = None           # خروجی analyze()

        self._build_style()
        self._build_menu()
        self._build_layout()

    # ------------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", font=(FONT_NAME, 9), rowheight=24)
        style.configure("Treeview.Heading", font=(FONT_NAME, 9, "bold"))
        style.configure("TLabel", font=(FONT_NAME, 10))
        style.configure("TButton", font=(FONT_NAME, 10))
        style.configure("Header.TLabel", font=(FONT_NAME, 13, "bold"))
        style.configure("Verdict.TLabel", font=(FONT_NAME, 12, "bold"))

    def _build_menu(self):
        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="باز کردن فایل‌های لاگ...", command=self.open_files, accelerator="Ctrl+O")
        filemenu.add_command(label="پاک کردن همه و شروع مجدد", command=self.reset_all)
        filemenu.add_separator()
        filemenu.add_command(label="خروجی گزارش HTML...", command=self.export_report)
        filemenu.add_separator()
        filemenu.add_command(label="خروج", command=self.destroy)
        menubar.add_cascade(label="فایل", menu=filemenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="درباره برنامه", command=self.show_about)
        menubar.add_cascade(label="راهنما", menu=helpmenu)

        self.config(menu=menubar)
        self.bind("<Control-o>", lambda e: self.open_files())

    def _build_layout(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text=APP_TITLE, style="Header.TLabel").pack(side="right")

        btn_frame = ttk.Frame(top)
        btn_frame.pack(side="left")
        ttk.Button(btn_frame, text="+ افزودن فایل لاگ", command=self.open_files).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="خروجی HTML", command=self.export_report).pack(side="left", padx=4)
        ttk.Button(btn_frame, text="پاک‌سازی", command=self.reset_all).pack(side="left", padx=4)

        self.files_label = ttk.Label(self, text="هیچ فایلی بارگذاری نشده است.", foreground="#555")
        self.files_label.pack(fill="x", padx=12)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=8)

        self.tab_summary = ttk.Frame(self.notebook)
        self.tab_events = ttk.Frame(self.notebook)
        self.tab_recs = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_summary, text="خلاصه و آمار")
        self.notebook.add(self.tab_events, text="جدول رویدادها")
        self.notebook.add(self.tab_recs, text="اولویت‌ها و توصیه‌ها")

        self._build_summary_tab()
        self._build_events_tab()
        self._build_recs_tab()

        self.status = ttk.Label(self, text="آماده.", relief="sunken", anchor="w", padding=4)
        self.status.pack(fill="x", side="bottom")

    # ------------------------------------------------------------------
    def _build_summary_tab(self):
        frame = self.tab_summary
        left = ttk.Frame(frame, padding=10)
        left.pack(side="right", fill="y")
        right = ttk.Frame(frame, padding=10)
        right.pack(side="left", fill="both", expand=True)

        self.verdict_label = ttk.Label(left, text="—", style="Verdict.TLabel", wraplength=320, justify="right")
        self.verdict_label.pack(anchor="ne", pady=(0, 4))
        self.verdict_desc = ttk.Label(left, text="", wraplength=320, justify="right")
        self.verdict_desc.pack(anchor="ne", pady=(0, 12))

        self.stats_text = tk.Text(left, width=42, height=20, font=(FONT_NAME, 9),
                                   wrap="word", relief="flat", bg=self.cget("bg"))
        self.stats_text.pack(fill="both", expand=True)
        self.stats_text.tag_configure("right", justify="right")
        self.stats_text.config(state="disabled")

        self.chart_severity = BarChart(right, width=480, height=200)
        self.chart_severity.pack(pady=8)
        self.chart_threats = BarChart(right, width=480, height=220)
        self.chart_threats.pack(pady=8)

    def _build_events_tab(self):
        frame = self.tab_events
        cols = ("time", "severity", "source", "threat", "action", "host", "risk")
        headers = {
            "time": "زمان", "severity": "شدت", "source": "منبع", "threat": "نام تهدید",
            "action": "اقدام", "host": "میزبان", "risk": "امتیاز ریسک",
        }
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        for c in cols:
            self.tree.heading(c, text=headers[c], command=lambda cc=c: self._sort_tree(cc))
            width = 150 if c not in ("threat",) else 260
            self.tree.column(c, width=width, anchor="center")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="top", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_event_select)
        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, background=self._tint(color))

        detail_frame = ttk.LabelFrame(frame, text="توضیح کامل رویداد انتخاب‌شده", padding=8)
        detail_frame.pack(fill="both", expand=False, padx=8, pady=(0, 8))
        self.detail_text = tk.Text(detail_frame, height=10, font=(FONT_NAME, 10), wrap="word")
        self.detail_text.pack(fill="both", expand=True)
        self.detail_text.tag_configure("right", justify="right")
        self.detail_text.config(state="disabled")

    def _build_recs_tab(self):
        frame = self.tab_recs
        ttk.Label(frame, text="مهم‌ترین رویدادها بر اساس امتیاز ریسک (نیازمند بررسی اولویت‌دار):",
                  style="Header.TLabel", padding=10).pack(anchor="ne")
        container = ttk.Frame(frame)
        container.pack(fill="both", expand=True, padx=8, pady=4)

        canvas = tk.Canvas(container, borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.recs_inner = ttk.Frame(canvas)
        self.recs_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.recs_inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ------------------------------------------------------------------
    @staticmethod
    def _tint(hex_color, factor=0.82):
        hex_color = hex_color.lstrip("#")
        r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
        r = int(r + (255 - r) * factor)
        g = int(g + (255 - g) * factor)
        b = int(b + (255 - b) * factor)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _sort_tree(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try:
            items.sort(key=lambda t: float(t[0]))
        except ValueError:
            items.sort(key=lambda t: t[0])
        for i, (_, k) in enumerate(items):
            self.tree.move(k, "", i)

    # ------------------------------------------------------------------
    def open_files(self):
        paths = filedialog.askopenfilenames(
            title="انتخاب فایل(های) لاگ آنتی‌ویروس/EDR",
            filetypes=[
                ("همه فایل‌های پشتیبانی‌شده", "*.csv *.json *.txt *.log"),
                ("CSV", "*.csv"), ("JSON", "*.json"),
                ("Text/Log", "*.txt *.log"), ("همه فایل‌ها", "*.*"),
            ],
        )
        if not paths:
            return
        errors = []
        added = 0
        for p in paths:
            try:
                events, filetype, product = parse_file(p)
                self.raw_events.extend(events)
                self.loaded_files.append((p, filetype, product, len(events)))
                added += len(events)
            except Exception as e:
                errors.append(f"{os.path.basename(p)}: {e}")

        self._refresh_files_label()
        if errors:
            messagebox.showwarning("خطا در برخی فایل‌ها", "\n".join(errors))
        if added:
            self.status.config(text=f"{added} رویداد جدید بارگذاری شد. در حال تحلیل...")
            self.after(50, self.run_analysis)

    def _refresh_files_label(self):
        if not self.loaded_files:
            self.files_label.config(text="هیچ فایلی بارگذاری نشده است.")
            return
        parts = []
        for path, filetype, product, count in self.loaded_files:
            label = PRODUCT_LABELS.get(product, "عمومی")
            parts.append(f"{os.path.basename(path)} ({label}, {count} رویداد)")
        self.files_label.config(text="فایل‌های بارگذاری‌شده: " + " | ".join(parts))

    def reset_all(self):
        self.loaded_files.clear()
        self.raw_events.clear()
        self.result = None
        self._refresh_files_label()
        for i in self.tree.get_children():
            self.tree.delete(i)
        for w in self.recs_inner.winfo_children():
            w.destroy()
        self.verdict_label.config(text="—")
        self.verdict_desc.config(text="")
        self._set_text(self.stats_text, "")
        self.chart_severity.delete("all")
        self.chart_threats.delete("all")
        self.status.config(text="آماده.")

    # ------------------------------------------------------------------
    def run_analysis(self):
        try:
            self.result = analyze(self.raw_events)
        except Exception:
            messagebox.showerror("خطا در تحلیل", traceback.format_exc())
            return
        self._populate_summary()
        self._populate_events()
        self._populate_recs()
        self.status.config(text=f"تحلیل کامل شد — {self.result['summary']['total']} رویداد پردازش شد.")

    def _populate_summary(self):
        s = self.result["summary"]
        verdict, desc = s["verdict"]
        color = {"بحرانی": "#c0392b", "نیازمند توجه": "#e67e22", "عادی": "#27ae60", "بدون داده": "#7f8c8d"}
        self.verdict_label.config(text=f"وضعیت کلی: {verdict}", foreground=color.get(verdict, "black"))
        self.verdict_desc.config(text=desc)

        lines = []
        lines.append(f"مجموع رویدادها: {s['total']}\n")
        lines.append("توزیع شدت:")
        for k, v in sorted(s["severity_counts"].items(), key=lambda x: -x[1]):
            lines.append(f"  • {k}: {v}")
        lines.append("\nوضعیت مهار تهدید:")
        for k, v in s["action_status"].items():
            lines.append(f"  • {k}: {v}")
        lines.append("\nمنابع لاگ:")
        for k, v in s["source_counts"].items():
            lines.append(f"  • {k}: {v}")
        if s["tactic_counts"]:
            lines.append("\nتاکتیک‌های MITRE مشاهده‌شده:")
            for k, v in sorted(s["tactic_counts"].items(), key=lambda x: -x[1]):
                lines.append(f"  • {k}: {v}")
        if s["hosts_affected"]:
            lines.append("\nمیزبان‌های درگیر (بیشترین رویداد):")
            for host, cnt in s["hosts_affected"][:8]:
                lines.append(f"  • {host}: {cnt}")

        self._set_text(self.stats_text, "\n".join(lines))

        sev_order = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
        sev_data = [(k, s["severity_counts"].get(k, 0)) for k in sev_order if s["severity_counts"].get(k, 0) > 0]
        self.chart_severity.draw(sev_data, colors=SEVERITY_COLORS, title="توزیع شدت رویدادها")

        top_threats_data = [(name, cnt) for name, cnt in s["top_threats"][:6]]
        self.chart_threats.draw(top_threats_data, title="پرتکرارترین تهدیدها")

    def _set_text(self, widget, content):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content, "right")
        widget.config(state="disabled")

    def _populate_events(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._event_lookup = {}
        for idx, ev in enumerate(self.result["events"]):
            ts = ev.get("timestamp")
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts or "")
            iid = str(idx)
            self.tree.insert("", "end", iid=iid, values=(
                ts_str, ev.get("severity", ""), ev.get("source", ""),
                ev.get("threat_name", ""), ev.get("action", "") or "—",
                ev.get("host", "") or "—", ev.get("risk_score", 0),
            ), tags=(ev.get("severity", "Unknown"),))
            self._event_lookup[iid] = ev

    def _on_event_select(self, _evt):
        sel = self.tree.selection()
        if not sel:
            return
        ev = self._event_lookup.get(sel[0])
        if not ev:
            return
        text = ev["explanation"]
        if ev.get("recommendations"):
            text += "\n\nپیشنهاد اقدام:\n" + "\n".join(f"  - {r}" for r in ev["recommendations"])
        self._set_text(self.detail_text, text)

    def _populate_recs(self):
        for w in self.recs_inner.winfo_children():
            w.destroy()
        hp = self.result["high_priority"]
        if not hp:
            ttk.Label(self.recs_inner, text="موردی با اولویت بالا یافت نشد. وضعیت مناسب است.",
                      padding=10).pack(anchor="ne")
            return
        for i, ev in enumerate(hp, 1):
            box = ttk.LabelFrame(
                self.recs_inner,
                text=f"{i}. [{ev.get('severity')}] {ev.get('threat_name')}  —  امتیاز ریسک: {ev.get('risk_score')}",
                padding=8,
            )
            box.pack(fill="x", expand=True, padx=6, pady=5)
            body = ev["explanation"] + "\n\nپیشنهاد اقدام:\n" + "\n".join(f"  - {r}" for r in ev["recommendations"])
            lbl = tk.Text(box, height=body.count("\n") + 2, font=(FONT_NAME, 9), wrap="word",
                           relief="flat", bg=self.cget("bg"))
            lbl.insert("1.0", body, "right")
            lbl.tag_configure("right", justify="right")
            lbl.config(state="disabled")
            lbl.pack(fill="x", expand=True)

    # ------------------------------------------------------------------
    def export_report(self):
        if not self.result:
            messagebox.showinfo("گزارشی موجود نیست", "ابتدا حداقل یک فایل لاگ بارگذاری کنید.")
            return
        path = filedialog.asksaveasfilename(
            title="ذخیره گزارش HTML",
            defaultextension=".html",
            filetypes=[("HTML", "*.html")],
            initialfile=f"AV-EDR-Report-{datetime.now().strftime('%Y%m%d-%H%M')}.html",
        )
        if not path:
            return
        try:
            html = build_html_report(self.result, [f[0] for f in self.loaded_files])
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            messagebox.showinfo("موفق", f"گزارش با موفقیت ذخیره شد:\n{path}")
        except Exception:
            messagebox.showerror("خطا در ذخیره گزارش", traceback.format_exc())

    def show_about(self):
        messagebox.showinfo(
            "درباره برنامه",
            f"{APP_TITLE}\n\n"
            "ابزار تحلیل و توضیح لاگ‌های آنتی‌ویروس و EDR\n"
            "پشتیبانی از: Windows Defender، CrowdStrike، SentinelOne، Carbon Black و فرمت‌های عمومی CSV/JSON/متنی.\n\n"
            "توجه: تشخیص‌های MITRE ATT&CK بر اساس تطبیق کلیدواژه است و جایگزین بررسی تخصصی نمی‌شود.",
        )


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
