import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import re
import json
import csv
from collections import Counter
import os
from datetime import datetime


class LogAnalyzerApp:

    def __init__(self, root):

        self.root = root
        self.root.title("Advanced Security Log Analyzer")
        self.root.geometry("780x600")

        self.log_file = None

        self.events = []

        self.ip_counter = Counter()
        self.user_counter = Counter()
        self.attack_types = Counter()

        self.setup_ui()


    def setup_ui(self):

        controls = tk.Frame(self.root)
        controls.pack(pady=15)

        self.load_btn = tk.Button(
            controls,
            text="Load Log File",
            command=self.load_log,
            bg="#0052cc",
            fg="white",
            font=("Arial",10,"bold")
        )
        self.load_btn.grid(row=0,column=0,padx=10)

        self.analyze_btn = tk.Button(
            controls,
            text="Analyze Security Events",
            command=self.analyze_log,
            state=tk.DISABLED,
            bg="green",
            fg="white"
        )
        self.analyze_btn.grid(row=0,column=1,padx=10)

        self.file_label = tk.Label(self.root,text="No file loaded",fg="gray")
        self.file_label.pack()

        report_frame = tk.Frame(self.root)
        report_frame.pack(fill=tk.BOTH,expand=True,padx=20,pady=10)

        tk.Label(report_frame,text="Security Analysis Report").pack(anchor="w")

        self.report = scrolledtext.ScrolledText(
            report_frame,
            font=("Consolas",10),
            state=tk.DISABLED
        )
        self.report.pack(fill=tk.BOTH,expand=True)

        export = tk.Frame(self.root)
        export.pack(pady=10)

        self.export_json_btn = tk.Button(
            export,
            text="Export JSON",
            command=self.export_json,
            state=tk.DISABLED
        )
        self.export_json_btn.grid(row=0,column=0,padx=10)

        self.export_csv_btn = tk.Button(
            export,
            text="Export CSV",
            command=self.export_csv,
            state=tk.DISABLED
        )
        self.export_csv_btn.grid(row=0,column=1,padx=10)


    def show_report(self,text):

        self.report.config(state=tk.NORMAL)
        self.report.delete(1.0,tk.END)
        self.report.insert(tk.END,text)
        self.report.config(state=tk.DISABLED)


    def load_log(self):

        file = filedialog.askopenfilename(title="Select log file")

        if file:

            self.log_file = file
            self.file_label.config(text=os.path.basename(file),fg="black")

            self.analyze_btn.config(state=tk.NORMAL)

            self.show_report("Log loaded. Click Analyze.")


    def analyze_log(self):

        self.events.clear()
        self.ip_counter.clear()
        self.user_counter.clear()
        self.attack_types.clear()

        ssh_regex = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")

        sql_regex = re.compile(r"(SELECT|UNION|DROP|INSERT).*HTTP",re.I)

        xss_regex = re.compile(r"<script>|%3Cscript",re.I)

        scan_regex = re.compile(r"(wp-admin|phpmyadmin|\.env|/etc/passwd)",re.I)

        try:

            with open(self.log_file,"r",errors="ignore") as f:

                for line in f:

                    ssh = ssh_regex.search(line)

                    if ssh:

                        ip = ssh.group("ip")
                        user = ssh.group("user")

                        self.ip_counter[ip]+=1
                        self.user_counter[user]+=1
                        self.attack_types["SSH Brute Force"]+=1

                        self.events.append({
                            "type":"SSH Brute Force",
                            "ip":ip,
                            "user":user
                        })

                    if sql_regex.search(line):

                        self.attack_types["SQL Injection"]+=1

                    if xss_regex.search(line):

                        self.attack_types["XSS Attempt"]+=1

                    if scan_regex.search(line):

                        self.attack_types["Directory Scan"]+=1


            self.generate_report()

            self.export_json_btn.config(state=tk.NORMAL)
            self.export_csv_btn.config(state=tk.NORMAL)

        except Exception as e:

            messagebox.showerror("Error",str(e))


    def generate_report(self):

        total = sum(self.attack_types.values())

        if total==0:

            self.show_report("No security events detected.")
            return

        report = "==== SECURITY INCIDENT REPORT ====\n\n"

        report += f"Generated: {datetime.now()}\n\n"

        report += f"Total Suspicious Events: {total}\n\n"

        report += "Attack Type Breakdown:\n"

        for k,v in self.attack_types.items():

            report += f"  {k}: {v}\n"


        report += "\nTop Attacker IPs:\n"

        for ip,count in self.ip_counter.most_common(5):

            report += f"  {ip}: {count} attempts\n"


        report += "\nTop Targeted Users:\n"

        for user,count in self.user_counter.most_common(5):

            report += f"  {user}: {count} attempts\n"


        threat_score = total + sum(self.ip_counter.values())

        report += "\nThreat Score: "

        if threat_score > 100:

            report += "CRITICAL\n"

        elif threat_score > 40:

            report += "HIGH\n"

        elif threat_score > 10:

            report += "MEDIUM\n"

        else:

            report += "LOW\n"


        self.show_report(report)


    def export_json(self):

        report = {
            "generated":str(datetime.now()),
            "events":self.events,
            "top_ips":dict(self.ip_counter.most_common(10)),
            "top_users":dict(self.user_counter.most_common(10)),
            "attack_types":dict(self.attack_types)
        }

        path = filedialog.asksaveasfilename(defaultextension=".json")

        if path:

            with open(path,"w") as f:
                json.dump(report,f,indent=4)

            messagebox.showinfo("Export","JSON report saved.")


    def export_csv(self):

        path = filedialog.asksaveasfilename(defaultextension=".csv")

        if path:

            with open(path,"w",newline="") as f:

                writer = csv.writer(f)

                writer.writerow(["Attack Type","IP","User"])

                for e in self.events:

                    writer.writerow([e["type"],e.get("ip",""),e.get("user","")])

            messagebox.showinfo("Export","CSV report saved.")



if __name__ == "__main__":

    root = tk.Tk()

    app = LogAnalyzerApp(root)

    root.mainloop()