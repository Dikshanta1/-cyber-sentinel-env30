import csv
import json
import os
import sqlite3
from typing import Any, Dict, List, Set


class Task:
    report_path = "final_report.json"

    def __init__(self, name: str, difficulty: str, objective: str):
        self.name = name
        self.difficulty = difficulty
        self.objective = objective

    def setup(self, jail_dir: str):
        raise NotImplementedError

    def grade(self, output_history: List[str], jail_dir: str, evidence: Set[str]) -> float:
        raise NotImplementedError

    def evidence_from_step(self, command: str, output: str, error: bool) -> Set[str]:
        return set()

    def _load_report(self, jail_dir: str) -> Dict[str, Any]:
        path = os.path.join(jail_dir, self.report_path)
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _history(self, output_history: List[str]) -> str:
        return "\n".join(output_history).lower()

    def _used_reader(self, command: str, path: str) -> bool:
        lowered = command.lower()
        readers = ("cat ", "grep ", "egrep ", "fgrep ", "sed ", "awk ", "head ", "tail ", "less ", "more ", "file ")
        return path.lower() in lowered and lowered.strip().startswith(readers)

    def _used_finder(self, command: str) -> bool:
        return command.lower().strip().startswith(("find ", "ls "))


class PhishingTriageTask(Task):
    def __init__(self):
        super().__init__(
            "phishing_triage",
            "easy",
            "Triage a suspicious email, identify the malicious indicator, and write final_report.json.",
        )

    def setup(self, jail_dir: str):
        case_dir = os.path.join(jail_dir, "soc", "cases", "INC-1042")
        os.makedirs(case_dir, exist_ok=True)
        with open(os.path.join(case_dir, "alert.json"), "w", encoding="utf-8") as f:
            json.dump(
                {
                    "incident_id": "INC-1042",
                    "queue": "phishing",
                    "reported_by": "finance@acme.example",
                    "subject": "Payroll portal password reset",
                    "sender_ip": "198.51.100.23",
                },
                f,
                indent=2,
            )
        with open(os.path.join(case_dir, "message.eml"), "w", encoding="utf-8") as f:
            f.write(
                "From: Payroll Security <it-helpdesk@payrol1.example>\n"
                "To: finance@acme.example\n"
                "Subject: Payroll portal password reset\n\n"
                "Please verify your password before 17:00 at "
                "https://login-update.secure-mail.example/reset?id=8812\n"
            )
        with open(os.path.join(case_dir, "dns.log"), "w", encoding="utf-8") as f:
            f.write(
                "2026-04-26T08:14:02Z login-update.secure-mail.example A 203.0.113.77 reputation=malicious\n"
                "2026-04-26T08:14:12Z payroll.acme.example A 10.12.8.44 reputation=trusted\n"
            )

    def evidence_from_step(self, command: str, output: str, error: bool) -> Set[str]:
        if error:
            return set()
        found = set()
        if self._used_finder(command) and "soc/cases/inc-1042" in output.lower():
            found.add("case_discovered")
        if self._used_reader(command, "soc/cases/INC-1042/alert.json") and "finance@acme.example" in output:
            found.add("alert_read")
        if self._used_reader(command, "soc/cases/INC-1042/message.eml") and "login-update.secure-mail.example" in output:
            found.add("message_read")
        if self._used_reader(command, "soc/cases/INC-1042/dns.log") and "203.0.113.77" in output:
            found.add("dns_read")
        return found

    def grade(self, output_history: List[str], jail_dir: str, evidence: Set[str]) -> float:
        report = self._load_report(jail_dir)
        score = 0.01
        if "case_discovered" in evidence or "alert_read" in evidence:
            score += 0.14
        if "message_read" in evidence:
            score += 0.20
        if "dns_read" in evidence:
            score += 0.20
        verified = {"message_read", "dns_read"}.issubset(evidence)
        if verified and report.get("incident_id") == "INC-1042":
            score += 0.10
        if verified and report.get("malicious_domain") == "login-update.secure-mail.example":
            score += 0.15
        if verified and report.get("block_ip") == "203.0.113.77":
            score += 0.10
        if verified and str(report.get("severity", "")).lower() == "high":
            score += 0.10
        return min(round(score, 4), 1.0)


class PolicyDriftTask(Task):
    def __init__(self):
        super().__init__(
            "policy_drift",
            "medium",
            "Reconcile a changed security policy with endpoint evidence and produce a quarantine decision.",
        )

    def setup(self, jail_dir: str):
        base = os.path.join(jail_dir, "enterprise")
        os.makedirs(os.path.join(base, "policy"), exist_ok=True)
        os.makedirs(os.path.join(base, "edr"), exist_ok=True)
        with open(os.path.join(base, "policy", "network_access_v3.md"), "w", encoding="utf-8") as f:
            f.write(
                "# Network Access Policy v3\n"
                "- Contractors may use VPN only from approved countries: IN, US, GB.\n"
                "- Any contractor login from a disallowed country followed by data export must be quarantined.\n"
                "- Quarantine action is represented as {\"quarantine\": true, \"reason\": \"policy_drift_export\"}.\n"
            )
        rows = [
            ["time", "user", "role", "country", "event", "bytes_out"],
            ["2026-04-26T09:01:00Z", "mira.contractor", "contractor", "IN", "vpn_login", "0"],
            ["2026-04-26T09:04:00Z", "owen.contractor", "contractor", "RU", "vpn_login", "0"],
            ["2026-04-26T09:09:00Z", "owen.contractor", "contractor", "RU", "export_customer_csv", "982031"],
            ["2026-04-26T09:11:00Z", "ravi.employee", "employee", "DE", "export_customer_csv", "38122"],
        ]
        with open(os.path.join(base, "edr", "session_events.csv"), "w", encoding="utf-8", newline="") as f:
            csv.writer(f).writerows(rows)

    def evidence_from_step(self, command: str, output: str, error: bool) -> Set[str]:
        if error:
            return set()
        found = set()
        if self._used_reader(command, "enterprise/policy/network_access_v3.md") and "approved countries" in output:
            found.add("policy_read")
        if self._used_reader(command, "enterprise/edr/session_events.csv") and "owen.contractor" in output:
            found.add("events_read")
        return found

    def grade(self, output_history: List[str], jail_dir: str, evidence: Set[str]) -> float:
        report = self._load_report(jail_dir)
        score = 0.01
        if "policy_read" in evidence:
            score += 0.18
        if "events_read" in evidence:
            score += 0.18
        if {"policy_read", "events_read"}.issubset(evidence):
            score += 0.16
        verified = {"policy_read", "events_read"}.issubset(evidence)
        if verified and report.get("user") == "owen.contractor":
            score += 0.15
        if verified and report.get("quarantine") is True:
            score += 0.15
        if verified and report.get("reason") == "policy_drift_export":
            score += 0.12
        if verified and report.get("country") == "RU":
            score += 0.05
        return min(round(score, 4), 1.0)


class IncidentContainmentTask(Task):
    def __init__(self):
        super().__init__(
            "incident_containment",
            "hard",
            "Correlate SIEM, proxy, and identity data to build a containment plan for a compromised user.",
        )

    def setup(self, jail_dir: str):
        base = os.path.join(jail_dir, "ops")
        os.makedirs(os.path.join(base, "identity"), exist_ok=True)
        os.makedirs(os.path.join(base, "proxy"), exist_ok=True)
        db_path = os.path.join(base, "siem.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE alerts (incident_id TEXT, user TEXT, source_ip TEXT, rule TEXT, severity TEXT)")
        cur.executemany(
            "INSERT INTO alerts VALUES (?, ?, ?, ?, ?)",
            [
                ("INC-771", "devon", "10.4.5.22", "impossible_travel", "medium"),
                ("INC-773", "anika", "10.9.8.17", "token_reuse_after_phish", "critical"),
                ("INC-774", "liam", "10.1.1.9", "rare_admin_tool", "low"),
            ],
        )
        conn.commit()
        conn.close()
        with open(os.path.join(base, "identity", "auth.log"), "w", encoding="utf-8") as f:
            f.write(
                "2026-04-26T10:31:00Z user=anika source_ip=10.9.8.17 mfa=push_approved session=sess-4431\n"
                "2026-04-26T10:36:00Z user=anika source_ip=10.9.8.17 token_reuse=true session=sess-4431\n"
                "2026-04-26T10:39:00Z user=devon source_ip=10.4.5.22 mfa=push_denied session=sess-1020\n"
            )
        with open(os.path.join(base, "proxy", "web.log"), "w", encoding="utf-8") as f:
            f.write(
                "2026-04-26T10:37:10Z user=anika host=cdn.safe.example bytes=4420\n"
                "2026-04-26T10:38:42Z user=anika host=exfil-drop.secure-mail.example bytes=741992\n"
                "2026-04-26T10:41:03Z user=liam host=docs.acme.example bytes=1190\n"
            )

    def evidence_from_step(self, command: str, output: str, error: bool) -> Set[str]:
        if error:
            return set()
        found = set()
        lowered = command.lower()
        if "ops/siem.db" in lowered and "inc-773" in output.lower() and "anika" in output.lower():
            found.add("siem_queried")
        if self._used_reader(command, "ops/identity/auth.log") and "token_reuse=true" in output:
            found.add("auth_read")
        if self._used_reader(command, "ops/proxy/web.log") and "exfil-drop.secure-mail.example" in output:
            found.add("proxy_read")
        return found

    def grade(self, output_history: List[str], jail_dir: str, evidence: Set[str]) -> float:
        report = self._load_report(jail_dir)
        block_domains = report.get("block_domains", [])
        if not isinstance(block_domains, list):
            block_domains = []
        score = 0.01
        if "siem_queried" in evidence:
            score += 0.15
        if "auth_read" in evidence:
            score += 0.15
        if "proxy_read" in evidence:
            score += 0.15
        verified = {"siem_queried", "auth_read", "proxy_read"}.issubset(evidence)
        if verified and report.get("incident_id") == "INC-773":
            score += 0.12
        if verified and report.get("user") == "anika":
            score += 0.10
        if verified and report.get("source_ip") == "10.9.8.17":
            score += 0.10
        if verified and report.get("revoke_session") is True:
            score += 0.10
        if verified and "exfil-drop.secure-mail.example" in block_domains:
            score += 0.12
        return min(round(score, 4), 1.0)


def get_task(task_name: str) -> Task:
    tasks = {
        "phishing_triage": PhishingTriageTask,
        "policy_drift": PolicyDriftTask,
        "incident_containment": IncidentContainmentTask,
    }
    if task_name not in tasks:
        raise ValueError(f"Unknown task {task_name!r}. Expected one of: {', '.join(tasks)}")
    return tasks[task_name]()
