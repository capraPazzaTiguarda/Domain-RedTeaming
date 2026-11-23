import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from config import APP_TITLE, WINDOW_SIZE
from core.normalizer import normalize_domain
from core.validator import is_valid_domain
from discovery.certificate_search import search_certificate_domains
from discovery.domain_search import find_similar_domains
from enrichment.dns_resolver import resolve_domain
from analysis.security_analyzer import assess_domain
from reports.report_generator import export_csv


class DomainAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(WINDOW_SIZE)
        self.minsize(900, 580)
        self.results = []
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        header = ttk.Frame(self, padding=(18, 16))
        header.pack(fill="x")
        ttk.Label(header, text="DOMAIN SECURITY ANALYZER",
                  font=("Segoe UI", 19, "bold")).pack(anchor="w")
        ttk.Label(header, text="Ricerca di domini potenzialmente simili e analisi DNS",
                  foreground="#666").pack(anchor="w", pady=(4, 0))

        search = ttk.LabelFrame(self, text="Dominio aziendale", padding=12)
        search.pack(fill="x", padx=18, pady=(0, 12))

        self.domain_var = tk.StringVar()
        entry = ttk.Entry(search, textvariable=self.domain_var, font=("Segoe UI", 12))
        entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        entry.insert(0, "azienda.it")
        entry.bind("<Return>", lambda _event: self.start_analysis())

        self.start_button = ttk.Button(search, text="Avvia analisi",
                                        command=self.start_analysis)
        self.start_button.pack(side="left")

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=18, pady=(0, 8))

        self.status_var = tk.StringVar(value="Pronto.")
        ttk.Label(self, textvariable=self.status_var,
                  padding=(18, 0)).pack(anchor="w")

        table_frame = ttk.Frame(self, padding=(18, 10))
        table_frame.pack(fill="both", expand=True)

        columns = ("domain", "similarity", "risk", "score", "ip", "mx")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        headings = {
            "domain": "Dominio",
            "similarity": "Somiglianza",
            "risk": "Rischio",
            "score": "Punteggio",
            "ip": "Record IP",
            "mx": "Record MX"
        }
        widths = {"domain": 260, "similarity": 110, "risk": 100,
                  "score": 100, "ip": 220, "mx": 220}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")

        yscroll = ttk.Scrollbar(table_frame, orient="vertical",
                                command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient="horizontal",
                                command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set,
                            xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        footer = ttk.Frame(self, padding=(18, 0, 18, 16))
        footer.pack(fill="x")
        ttk.Button(footer, text="Esporta CSV",
                   command=self.save_csv).pack(side="left")
        ttk.Label(footer,
                  text="Il punteggio è indicativo: verificare manualmente i risultati.",
                  foreground="#666").pack(side="right")

        self.tree.bind("<<TreeviewSelect>>", self.show_details)

    def start_analysis(self):
        domain = normalize_domain(self.domain_var.get())
        if not is_valid_domain(domain):
            messagebox.showerror("Dominio non valido",
                                 "Inserisci un dominio valido, ad esempio azienda.it")
            return

        self.domain_var.set(domain)
        self.start_button.config(state="disabled")
        self.progress.start(12)
        self.status_var.set(f"Ricerca in corso per {domain}...")
        self.results = []
        for row in self.tree.get_children():
            self.tree.delete(row)

        threading.Thread(target=self._analysis_worker,
                         args=(domain,), daemon=True).start()

    def _analysis_worker(self, domain):
        try:
            hosts = search_certificate_domains(domain)
            candidates = find_similar_domains(domain, hosts)
            results = []

            for candidate in candidates:
                dns_data = resolve_domain(candidate["domain"])
                risk = assess_domain(candidate, dns_data)
                results.append({**candidate, **dns_data, **risk})

            self.after(0, self._analysis_complete, results, None)
        except Exception as exc:
            self.after(0, self._analysis_complete, [], str(exc))

    def _analysis_complete(self, results, error):
        self.progress.stop()
        self.start_button.config(state="normal")

        if error:
            self.status_var.set("Analisi non completata.")
            messagebox.showerror(
                "Errore durante l'analisi",
                f"{error}\n\nControlla la connessione e riprova."
            )
            return

        self.results = results
        for item in results:
            ips = ", ".join(item.get("A", []) + item.get("AAAA", [])) or "—"
            mx = ", ".join(item.get("MX", [])) or "—"
            self.tree.insert("", "end", values=(
                item["domain"],
                f'{item["similarity"]}%',
                item["risk_level"],
                item["risk_score"],
                ips,
                mx
            ))

        self.status_var.set(
            f"Analisi terminata. Domini potenzialmente simili trovati: {len(results)}"
        )

        if not results:
            messagebox.showinfo(
                "Analisi terminata",
                "Nessun dominio simile individuato nelle fonti interrogate. "
                "Questo non garantisce che non esistano domini imitativi."
            )

    def show_details(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        domain = values[0]
        item = next((r for r in self.results if r["domain"] == domain), None)
        if not item:
            return

        details = (
            f"Dominio: {item['domain']}\n"
            f"Somiglianza: {item['similarity']}%\n"
            f"Rischio euristico: {item['risk_level']} ({item['risk_score']}/100)\n\n"
            f"Indicatori:\n- " + ("\n- ".join(item["reasons"]) or "Nessuno") +
            "\n\nDNS:\n"
        )
        for record in ("A", "AAAA", "MX", "NS", "CNAME"):
            details += f"{record}: {', '.join(item.get(record, [])) or '—'}\n"
        messagebox.showinfo("Dettagli dominio", details)

    def save_csv(self):
        if not self.results:
            messagebox.showinfo("Nessun risultato",
                                "Esegui prima un'analisi.")
            return
        destination = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("File CSV", "*.csv")],
            initialfile="domain_analysis.csv"
        )
        if not destination:
            return
        try:
            export_csv(self.results, destination)
            messagebox.showinfo("Esportazione completata",
                                f"Report salvato in:\n{destination}")
        except OSError as exc:
            messagebox.showerror("Errore esportazione", str(exc))
