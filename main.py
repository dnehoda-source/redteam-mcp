"""
RedTeam MCP Server — Natural Language Attack Simulation Platform
Integrates Stratus Red Team (cloud) + Atomic Red Team (endpoint) behind MCP.
v2.0 — Executive Reports, Cloud Reporting API, Web App Pentesting
"""

import json
import os
import subprocess
import yaml
import glob
import re
import ssl
import socket
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from mcp.server.fastmcp import FastMCP

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════

STRATUS_BIN = os.getenv("STRATUS_BIN", os.path.expanduser("~/bin/stratus"))
ATOMICS_PATH = os.getenv("ATOMICS_PATH", "/tmp/atomic-red-team/atomics")
GCP_PROJECT = os.getenv("GCP_PROJECT", "tito-436719")
LOG_DIR = os.getenv("REDTEAM_LOG_DIR", os.path.expanduser("~/redteam-logs"))
PORT = int(os.getenv("PORT", "8090"))

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format='{"severity":"%(levelname)s","message":"%(message)s","tool":"redteam-mcp"}')
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# IN-MEMORY REPORT STORE
# ═══════════════════════════════════════════════════════════════

REPORTS_STORE: list[dict] = []

# ═══════════════════════════════════════════════════════════════
# ATTACK TECHNIQUE INDEXES
# ═══════════════════════════════════════════════════════════════

# Natural language aliases for common attack concepts
ATTACK_ALIASES = {
    # Credential attacks
    "steal credentials": ["gcp.credential-access.secretmanager-retrieve-secrets", "T1552.001"],
    "credential theft": ["gcp.credential-access.secretmanager-retrieve-secrets", "T1552.001"],
    "dump secrets": ["gcp.credential-access.secretmanager-retrieve-secrets", "T1003"],
    "steal service account": ["gcp.initial-access.use-compute-sa-outside-gcp", "gcp.persistence.create-service-account-key"],
    "steal sa token": ["gcp.initial-access.use-compute-sa-outside-gcp"],
    "steal passwords": ["T1003", "T1552.001"],
    "mimikatz": ["T1003.001"],
    "kerberoast": ["T1558.003"],

    # Persistence
    "create backdoor": ["gcp.persistence.backdoor-service-account-policy", "gcp.persistence.create-admin-service-account", "T1136"],
    "backdoor": ["gcp.persistence.backdoor-service-account-policy", "T1547"],
    "create admin account": ["gcp.persistence.create-admin-service-account", "T1136.003"],
    "ssh key injection": ["gcp.lateral-movement.add-sshkey-instance-metadata", "T1098.004"],
    "invite external user": ["gcp.persistence.invite-external-user"],
    "persistence": ["gcp.persistence.create-service-account-key", "gcp.persistence.create-admin-service-account", "T1547", "T1136"],

    # Privilege escalation
    "privilege escalation": ["gcp.privilege-escalation.impersonate-service-accounts", "T1548", "T1078"],
    "privesc": ["gcp.privilege-escalation.impersonate-service-accounts", "T1548"],
    "impersonate": ["gcp.privilege-escalation.impersonate-service-accounts"],

    # Defense evasion
    "disable logging": ["gcp.defense-evasion.disable-audit-logs", "gcp.defense-evasion.delete-logging-sink", "gcp.defense-evasion.disable-logging-sink"],
    "cover tracks": ["gcp.defense-evasion.disable-audit-logs", "gcp.defense-evasion.delete-dns-logs", "T1070"],
    "delete logs": ["gcp.defense-evasion.delete-dns-logs", "gcp.defense-evasion.delete-logging-sink", "T1070.002"],
    "disable audit": ["gcp.defense-evasion.disable-audit-logs"],
    "evade detection": ["gcp.defense-evasion.disable-audit-logs", "gcp.defense-evasion.remove-vpc-flow-logs"],

    # Discovery / Recon
    "enumerate": ["gcp.discovery.enumerate-permissions", "gcp.discovery.download-instance-metadata", "T1087"],
    "recon": ["gcp.discovery.enumerate-permissions", "gcp.discovery.download-instance-metadata", "T1046"],
    "scan": ["T1046", "gcp.discovery.enumerate-permissions"],
    "discovery": ["gcp.discovery.enumerate-permissions", "gcp.discovery.download-instance-metadata"],

    # Exfiltration
    "exfiltrate": ["gcp.exfiltration.share-compute-disk", "gcp.exfiltration.share-compute-image", "gcp.exfiltration.share-compute-snapshot"],
    "data theft": ["gcp.exfiltration.share-compute-disk", "T1567"],
    "steal data": ["gcp.exfiltration.share-compute-disk", "gcp.exfiltration.share-compute-snapshot"],

    # Lateral movement
    "lateral movement": ["gcp.lateral-movement.add-sshkey-instance-metadata", "T1021"],
    "move laterally": ["gcp.lateral-movement.add-sshkey-instance-metadata", "T1021"],
    "pivot": ["gcp.lateral-movement.add-sshkey-instance-metadata", "T1021"],

    # Impact
    "cryptomining": ["gcp.impact.create-gpu-vm"],
    "resource abuse": ["gcp.impact.create-gpu-vm", "gcp.impact.create-instances-in-multiple-zones"],
    "ransomware": ["T1486"],

    # PowerShell
    "powershell": ["T1059.001"],
    "command execution": ["T1059.001", "T1059.004"],
    "reverse shell": ["T1059.004"],

    # Full exercises
    "full attack chain": ["gcp.discovery.enumerate-permissions", "gcp.credential-access.secretmanager-retrieve-secrets",
                          "gcp.persistence.create-admin-service-account", "gcp.privilege-escalation.impersonate-service-accounts",
                          "gcp.defense-evasion.disable-audit-logs", "gcp.exfiltration.share-compute-disk"],
    "purple team": ["gcp.discovery.enumerate-permissions", "gcp.credential-access.secretmanager-retrieve-secrets",
                    "gcp.persistence.create-service-account-key", "gcp.defense-evasion.disable-audit-logs"],
    "cloud kill chain": ["gcp.discovery.enumerate-permissions", "gcp.credential-access.secretmanager-retrieve-secrets",
                         "gcp.persistence.create-admin-service-account", "gcp.privilege-escalation.impersonate-service-accounts",
                         "gcp.defense-evasion.disable-audit-logs", "gcp.exfiltration.share-compute-disk"],
}

# MITRE ATT&CK tactic mapping
TACTIC_MAP = {
    "reconnaissance": "discovery",
    "initial-access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege-escalation": "privilege-escalation",
    "defense-evasion": "defense-evasion",
    "credential-access": "credential-access",
    "discovery": "discovery",
    "lateral-movement": "lateral-movement",
    "collection": "collection",
    "exfiltration": "exfiltration",
    "impact": "impact",
}


def _load_stratus_techniques():
    """Load all Stratus Red Team GCP techniques."""
    try:
        result = subprocess.run(
            [STRATUS_BIN, "list", "--platform", "gcp"],
            capture_output=True, text=True, timeout=10
        )
        techniques = {}
        for line in result.stdout.split("\n"):
            if "|" not in line or "---" in line or "TECHNIQUE ID" in line:
                continue
            parts = [p.strip() for p in line.split("|")]
            parts = [p for p in parts if p]
            if len(parts) >= 3 and parts[0].startswith("gcp."):
                tid = parts[0]
                name = parts[1]
                tactic = parts[3] if len(parts) > 3 else parts[2]
                techniques[tid] = {"id": tid, "name": name, "tactic": tactic, "platform": "gcp", "engine": "stratus"}
        return techniques
    except Exception as e:
        logger.error(f"Failed to load Stratus techniques: {e}")
        return {}


def _load_atomic_techniques():
    """Load Atomic Red Team technique index from YAML files."""
    techniques = {}
    try:
        for yaml_file in glob.glob(f"{ATOMICS_PATH}/T*/T*.yaml"):
            tid = Path(yaml_file).stem
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)
            if not data:
                continue
            tests = data.get("atomic_tests", [])
            platforms = set()
            for t in tests:
                platforms.update(t.get("supported_platforms", []))
            techniques[tid] = {
                "id": tid,
                "name": data.get("display_name", tid),
                "mitre_id": data.get("attack_technique", tid),
                "test_count": len(tests),
                "platforms": list(platforms),
                "engine": "atomic",
            }
    except Exception as e:
        logger.error(f"Failed to load Atomic techniques: {e}")
    return techniques


STRATUS_TECHNIQUES = _load_stratus_techniques()
ATOMIC_TECHNIQUES = _load_atomic_techniques()

logger.info(f"RedTeam MCP: {len(STRATUS_TECHNIQUES)} Stratus GCP techniques, {len(ATOMIC_TECHNIQUES)} Atomic Red Team techniques loaded")


# ═══════════════════════════════════════════════════════════════
# NATURAL LANGUAGE → TECHNIQUE RESOLVER
# ═══════════════════════════════════════════════════════════════

def resolve_techniques(query: str) -> list:
    """Resolve a natural language query to a list of attack technique IDs."""
    query_lower = query.lower().strip()
    matched = []

    # 1. Direct technique ID match
    if re.match(r"^(gcp\.|aws\.|azure\.|T\d{4})", query_lower):
        return [query_lower]

    # 2. Alias match
    for alias, technique_ids in ATTACK_ALIASES.items():
        if alias in query_lower or query_lower in alias:
            matched.extend(technique_ids)

    # 3. MITRE tactic match
    for tactic_name, tactic_key in TACTIC_MAP.items():
        if tactic_name in query_lower:
            for tid, tech in STRATUS_TECHNIQUES.items():
                if tactic_key in tech.get("tactic", "").lower():
                    matched.append(tid)

    # 4. Keyword search across technique names
    if not matched:
        keywords = query_lower.split()
        for tid, tech in {**STRATUS_TECHNIQUES, **ATOMIC_TECHNIQUES}.items():
            name_lower = tech.get("name", "").lower()
            if all(kw in name_lower or kw in tid.lower() for kw in keywords):
                matched.append(tid)

    # Deduplicate preserving order
    seen = set()
    unique = []
    for t in matched:
        if t not in seen:
            seen.add(t)
            unique.append(t)

    return unique


# ═══════════════════════════════════════════════════════════════
# ATTACK EXECUTION ENGINES
# ═══════════════════════════════════════════════════════════════

def _run_stratus(technique_id: str, action: str = "detonate", project: str = None) -> dict:
    """Execute a Stratus Red Team technique."""
    env = os.environ.copy()
    if project:
        env["GOOGLE_PROJECT"] = project

    cmd = [STRATUS_BIN, action, technique_id]
    logger.info(f"Stratus: {' '.join(cmd)} (project={project or GCP_PROJECT})")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
        output = {
            "engine": "stratus",
            "technique": technique_id,
            "action": action,
            "exit_code": result.returncode,
            "stdout": result.stdout[-2000:] if result.stdout else "",
            "stderr": result.stderr[-1000:] if result.stderr else "",
            "success": result.returncode == 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        log_file = os.path.join(LOG_DIR, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{technique_id.replace('.', '_')}.json")
        with open(log_file, "w") as f:
            json.dump(output, f, indent=2)
        return output
    except subprocess.TimeoutExpired:
        return {"engine": "stratus", "technique": technique_id, "error": "Execution timed out (300s)", "success": False}
    except Exception as e:
        return {"engine": "stratus", "technique": technique_id, "error": str(e), "success": False}


def _run_atomic(technique_id: str, test_index: int = 0, platform: str = "linux") -> dict:
    """Execute an Atomic Red Team test by parsing and running the YAML command."""
    yaml_file = os.path.join(ATOMICS_PATH, technique_id, f"{technique_id}.yaml")
    if not os.path.exists(yaml_file):
        return {"engine": "atomic", "technique": technique_id, "error": f"Technique {technique_id} not found", "success": False}

    try:
        with open(yaml_file, "r") as f:
            data = yaml.safe_load(f)

        tests = data.get("atomic_tests", [])
        compatible = [t for t in tests if platform in t.get("supported_platforms", [])]
        if not compatible:
            return {"engine": "atomic", "technique": technique_id, "error": f"No {platform}-compatible tests found", "success": False,
                    "available_platforms": list(set(p for t in tests for p in t.get("supported_platforms", [])))}

        test = compatible[min(test_index, len(compatible) - 1)]
        executor = test.get("executor", {})
        command = executor.get("command", "")
        executor_name = executor.get("name", "sh")

        for arg_name, arg_def in test.get("input_arguments", {}).items():
            default_val = str(arg_def.get("default", ""))
            command = command.replace(f"#{{{arg_name}}}", default_val)

        command = command.replace("PathToAtomicsFolder", ATOMICS_PATH)

        output = {
            "engine": "atomic",
            "technique": technique_id,
            "test_name": test.get("name", ""),
            "description": test.get("description", "")[:500],
            "command_preview": command[:500],
            "executor": executor_name,
            "elevation_required": executor.get("elevation_required", False),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if executor_name in ["sh", "bash", "command_prompt"]:
            shell_cmd = ["bash", "-c", command]
        elif executor_name == "powershell":
            shell_cmd = ["pwsh", "-Command", command]
        else:
            output["error"] = f"Unsupported executor: {executor_name}"
            output["success"] = False
            return output

        result = subprocess.run(shell_cmd, capture_output=True, text=True, timeout=120)
        output["exit_code"] = result.returncode
        output["stdout"] = result.stdout[-2000:] if result.stdout else ""
        output["stderr"] = result.stderr[-1000:] if result.stderr else ""
        output["success"] = result.returncode == 0

        log_file = os.path.join(LOG_DIR, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{technique_id}.json")
        with open(log_file, "w") as f:
            json.dump(output, f, indent=2)

        return output

    except subprocess.TimeoutExpired:
        return {"engine": "atomic", "technique": technique_id, "error": "Execution timed out (120s)", "success": False}
    except Exception as e:
        return {"engine": "atomic", "technique": technique_id, "error": str(e), "success": False}


# ═══════════════════════════════════════════════════════════════
# EXECUTIVE REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════

# Remediation recommendations keyed by tactic
_REMEDIATION_MAP = {
    "credential-access": [
        "Rotate all secrets and service account keys immediately",
        "Enable Secret Manager audit logging and alerting",
        "Implement least-privilege access to secret stores",
        "Deploy credential exposure detection rules in SIEM",
    ],
    "persistence": [
        "Audit all IAM policies for unauthorized bindings",
        "Alert on new service account key creation",
        "Monitor for unexpected admin account creation",
        "Enable org-level constraints on SA key creation",
    ],
    "privilege-escalation": [
        "Restrict service account impersonation with IAM conditions",
        "Monitor for unusual token generation or impersonation events",
        "Implement SCC findings for privilege escalation indicators",
        "Review and tighten org-level IAM roles",
    ],
    "defense-evasion": [
        "Create tamper-proof log sinks (locked retention policies)",
        "Alert on audit log configuration changes",
        "Export logs to an immutable external SIEM",
        "Monitor Cloud Audit Logs for admin.googleapis.com changes",
    ],
    "discovery": [
        "Alert on bulk permission enumeration (testIamPermissions calls)",
        "Monitor for metadata server access from unusual sources",
        "Restrict metadata endpoint access via firewall rules",
    ],
    "exfiltration": [
        "Enable VPC Service Controls for sensitive projects",
        "Alert on disk/image/snapshot sharing outside organization",
        "Monitor for data access from unexpected IP ranges",
    ],
    "lateral-movement": [
        "Restrict project-wide SSH key injection via OS Login",
        "Monitor for instance metadata modifications",
        "Enforce OS Login 2FA for SSH access",
    ],
    "initial-access": [
        "Rotate compromised service account credentials",
        "Enable Workload Identity Federation instead of exported keys",
        "Monitor for SA token usage from external IPs",
    ],
    "impact": [
        "Set compute quotas to prevent unauthorized resource creation",
        "Alert on GPU VM creation in non-standard zones",
        "Monitor billing anomalies for crypto-mining indicators",
    ],
    "execution": [
        "Deploy endpoint detection and response (EDR) tooling",
        "Monitor for suspicious process creation chains",
        "Restrict PowerShell/bash execution via application allowlisting",
    ],
}


def _extract_tactic(technique_id: str, tech_info: dict) -> str:
    """Extract the MITRE ATT&CK tactic from a technique."""
    if tech_info and tech_info.get("tactic"):
        return tech_info["tactic"].split(",")[0].strip().lower()
    # Parse from Stratus ID: gcp.<tactic>.<name>
    parts = technique_id.split(".")
    if len(parts) >= 2:
        return parts[1]
    return "unknown"


def _extract_mitre_id(technique_id: str, tech_info: dict) -> str:
    """Best-effort extraction of a MITRE ATT&CK T-code."""
    if technique_id.startswith("T"):
        return technique_id
    if tech_info and tech_info.get("mitre_id"):
        return tech_info["mitre_id"]
    return technique_id


def _build_report(query: str, results: list, project: str) -> dict:
    """Build a structured report dict and markdown from execution results."""
    report_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    total = len(results)
    succeeded = sum(1 for r in results if r.get("success"))
    failed = total - succeeded
    # detection_status is a placeholder — "Unknown" until SecOps integration
    # We assume: success = attack worked = potential gap; failure = attack blocked or errored
    detected = 0  # placeholder
    undetected = succeeded  # attacks that succeeded are assumed undetected until proven otherwise
    posture_score = round((detected / total * 100) if total else 0, 1)

    tactics_seen = set()
    technique_rows = []
    gaps = []

    for r in results:
        tid = r.get("technique", r.get("id", "unknown"))
        tech_info = STRATUS_TECHNIQUES.get(tid) or ATOMIC_TECHNIQUES.get(tid) or {}
        tactic = _extract_tactic(tid, tech_info)
        mitre_id = _extract_mitre_id(tid, tech_info)
        name = tech_info.get("name", r.get("test_name", tid))
        tactics_seen.add(tactic)
        status = "✅ Executed" if r.get("success") else ("❌ Failed" if r.get("error") else "⚠️ Unknown")
        detection = "🔍 Pending SecOps Integration"
        exec_time = r.get("timestamp", "N/A")

        technique_rows.append({
            "technique_id": mitre_id,
            "name": name,
            "tactic": tactic,
            "status": status,
            "exec_time": exec_time,
            "detection": detection,
            "success": r.get("success", False),
        })

        if r.get("success"):
            recs = _REMEDIATION_MAP.get(tactic, ["Review detection rules for this tactic"])
            gaps.append({
                "technique_id": mitre_id,
                "name": name,
                "tactic": tactic,
                "recommendations": recs,
            })

    # Threat level heuristic
    if total >= 5 and undetected >= 3:
        threat_level = "🔴 CRITICAL"
    elif total >= 3 and undetected >= 2:
        threat_level = "🟠 HIGH"
    elif undetected >= 1:
        threat_level = "🟡 MEDIUM"
    else:
        threat_level = "🟢 LOW"

    # Build markdown
    md_lines = []
    md_lines.append(f"# ☠️ Purple Team Executive Report")
    md_lines.append(f"")
    md_lines.append(f"**Report ID:** `{report_id}`")
    md_lines.append(f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    md_lines.append(f"**Target Project:** `{project}`")
    md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")
    md_lines.append(f"## 📋 Executive Summary")
    md_lines.append(f"")
    md_lines.append(f"| Metric | Value |")
    md_lines.append(f"|--------|-------|")
    md_lines.append(f"| **Threat Level** | {threat_level} |")
    md_lines.append(f"| **Techniques Tested** | {total} |")
    md_lines.append(f"| **Attacks Executed** | {succeeded} |")
    md_lines.append(f"| **Attacks Failed/Blocked** | {failed} |")
    md_lines.append(f"| **Attacks Detected** | {detected} (pending SecOps integration) |")
    md_lines.append(f"| **Detection Gaps** | {undetected} |")
    md_lines.append(f"| **Security Posture Score** | **{posture_score}%** |")
    md_lines.append(f"| **Scope** | {', '.join(sorted(tactics_seen)) or 'N/A'} |")
    md_lines.append(f"| **Attack Query** | _{query}_ |")
    md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")
    md_lines.append(f"## 🗺️ MITRE ATT&CK Coverage Map")
    md_lines.append(f"")
    all_tactics = ["discovery", "initial-access", "execution", "persistence", "privilege-escalation",
                   "defense-evasion", "credential-access", "lateral-movement", "collection", "exfiltration", "impact"]
    for t in all_tactics:
        marker = "✅ Tested" if t in tactics_seen else "⬜ Not Tested"
        md_lines.append(f"- **{t}**: {marker}")
    md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")
    md_lines.append(f"## 📊 Per-Technique Results")
    md_lines.append(f"")
    md_lines.append(f"| Technique ID | Name | Tactic | Status | Detection |")
    md_lines.append(f"|-------------|------|--------|--------|-----------|")
    for row in technique_rows:
        md_lines.append(f"| `{row['technique_id']}` | {row['name']} | {row['tactic']} | {row['status']} | {row['detection']} |")
    md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")
    md_lines.append(f"## 🔓 Detection Gap Analysis")
    md_lines.append(f"")
    if gaps:
        md_lines.append(f"The following {len(gaps)} attack(s) executed successfully with **no confirmed detection**.")
        md_lines.append(f"Each represents a potential blind spot requiring new detection rules.")
        md_lines.append(f"")
        for i, gap in enumerate(gaps, 1):
            md_lines.append(f"### Gap {i}: `{gap['technique_id']}` — {gap['name']}")
            md_lines.append(f"- **Tactic:** {gap['tactic']}")
            md_lines.append(f"- **Remediation:**")
            for rec in gap["recommendations"]:
                md_lines.append(f"  - {rec}")
            md_lines.append(f"")
    else:
        md_lines.append(f"✅ No detection gaps identified — all attacks were blocked or failed.")
        md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")
    md_lines.append(f"## ⏱️ Mean Time to Detect (MTTD)")
    md_lines.append(f"")
    md_lines.append(f"> ⚠️ **MTTD metrics require Google SecOps integration.**")
    md_lines.append(f"> Once connected, this section will show per-technique detection latency")
    md_lines.append(f"> measured from attack execution timestamp to first SIEM alert.")
    md_lines.append(f"")
    md_lines.append(f"| Technique | Attack Time | Detection Time | MTTD |")
    md_lines.append(f"|-----------|-------------|----------------|------|")
    for row in technique_rows:
        md_lines.append(f"| `{row['technique_id']}` | {row['exec_time']} | Pending | Pending |")
    md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")
    md_lines.append(f"## 🛡️ Security Posture Score")
    md_lines.append(f"")
    md_lines.append(f"**Overall Score: {posture_score}%** (detected / total attacks)")
    md_lines.append(f"")
    if posture_score == 0 and total > 0:
        md_lines.append(f"⚠️ Score is 0% because detection confirmation requires SecOps integration.")
        md_lines.append(f"This does not mean your defenses failed — it means detection status is unknown.")
    md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")
    md_lines.append(f"*Report generated by RedTeam MCP Server v2.0*")

    markdown = "\n".join(md_lines)

    report = {
        "id": report_id,
        "timestamp": now.isoformat(),
        "query": query,
        "project": project,
        "threat_level": threat_level,
        "total_techniques": total,
        "succeeded": succeeded,
        "failed": failed,
        "detected": detected,
        "undetected": undetected,
        "posture_score": posture_score,
        "tactics": sorted(tactics_seen),
        "technique_rows": technique_rows,
        "gaps": gaps,
        "markdown": markdown,
        "results_raw": results,
    }

    REPORTS_STORE.append(report)
    return report


# ═══════════════════════════════════════════════════════════════
# WEB APP PENTESTING ENGINE
# ═══════════════════════════════════════════════════════════════

_SECURITY_HEADERS = {
    "Content-Security-Policy": {"severity": "HIGH", "description": "Prevents XSS, clickjacking, and code injection"},
    "Strict-Transport-Security": {"severity": "HIGH", "description": "Enforces HTTPS connections"},
    "X-Frame-Options": {"severity": "MEDIUM", "description": "Prevents clickjacking via framing"},
    "X-Content-Type-Options": {"severity": "MEDIUM", "description": "Prevents MIME-type sniffing"},
    "X-XSS-Protection": {"severity": "LOW", "description": "Legacy XSS filter (modern CSP preferred)"},
    "Referrer-Policy": {"severity": "LOW", "description": "Controls referrer information leakage"},
    "Permissions-Policy": {"severity": "MEDIUM", "description": "Controls browser feature access"},
    "Cross-Origin-Opener-Policy": {"severity": "LOW", "description": "Isolates browsing context"},
    "Cross-Origin-Resource-Policy": {"severity": "LOW", "description": "Controls cross-origin resource loading"},
    "Cross-Origin-Embedder-Policy": {"severity": "LOW", "description": "Controls cross-origin embedding"},
}

_COMMON_PATHS = [
    "/admin", "/administrator", "/login", "/wp-admin", "/wp-login.php",
    "/api", "/api/v1", "/api/v2", "/api/docs", "/api/swagger",
    "/.env", "/.git", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn", "/.htaccess", "/.htpasswd", "/.DS_Store",
    "/debug", "/debug/default/view", "/debug/vars", "/debug/pprof",
    "/server-status", "/server-info", "/_status", "/_health",
    "/phpmyadmin", "/phpinfo.php", "/info.php",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/backup", "/backup.sql", "/database.sql", "/dump.sql",
    "/config", "/config.json", "/config.yml", "/config.xml",
    "/console", "/shell", "/actuator", "/actuator/env", "/actuator/health",
    "/.well-known/security.txt", "/security.txt",
    "/graphql", "/graphiql", "/__graphql",
    "/swagger.json", "/openapi.json", "/swagger-ui.html",
    "/wp-content", "/wp-includes", "/xmlrpc.php",
    "/cgi-bin", "/cgi-bin/test-cgi",
]

_EXTENDED_PATHS = _COMMON_PATHS + [
    "/test", "/staging", "/dev", "/development",
    "/internal", "/private", "/secret", "/hidden",
    "/uploads", "/upload", "/files", "/media",
    "/tmp", "/temp", "/cache", "/log", "/logs",
    "/old", "/bak", "/orig", "/copy",
    "/api/admin", "/api/internal", "/api/debug",
    "/status", "/health", "/healthcheck", "/ping", "/ready",
    "/metrics", "/prometheus", "/grafana",
    "/jenkins", "/ci", "/gitlab", "/travis",
    "/socket.io", "/sockjs", "/websocket",
    "/oauth", "/oauth2", "/auth", "/sso",
    "/register", "/signup", "/forgot", "/reset",
    "/install", "/setup", "/init",
]

_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime", "X-Generator"]

_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]

_REDIRECT_PARAMS = ["url", "redirect", "redirect_url", "redirect_uri", "return", "returnUrl",
                     "return_url", "next", "goto", "target", "to", "out", "rurl", "dest", "destination"]


def _check_security_headers(url: str) -> dict:
    """Check HTTP security headers for a URL."""
    if not _HAS_REQUESTS:
        return {"error": "requests library not available"}
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=True,
                            headers={"User-Agent": "RedTeam-MCP-SecurityScanner/2.0"})
        present = {}
        missing = {}
        for header, info in _SECURITY_HEADERS.items():
            val = resp.headers.get(header)
            if val:
                present[header] = {"value": val, "severity": info["severity"], "description": info["description"]}
            else:
                missing[header] = {"severity": info["severity"], "description": info["description"]}

        score = round(len(present) / len(_SECURITY_HEADERS) * 100, 1)
        return {
            "url": url,
            "status_code": resp.status_code,
            "headers_present": present,
            "headers_missing": missing,
            "score": score,
            "grade": "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D" if score >= 20 else "F",
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


def _check_ssl(url: str) -> dict:
    """Check SSL/TLS certificate validity."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        return {"url": url, "ssl": False, "note": "Not using HTTPS"}

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days
                return {
                    "url": url,
                    "ssl": True,
                    "valid": days_left > 0,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "not_before": not_before.isoformat(),
                    "not_after": not_after.isoformat(),
                    "days_until_expiry": days_left,
                    "protocol": ssock.version(),
                    "san": [entry[1] for entry in cert.get("subjectAltName", [])],
                    "warning": "Certificate expiring soon!" if 0 < days_left < 30 else None,
                }
    except ssl.SSLCertVerificationError as e:
        return {"url": url, "ssl": True, "valid": False, "error": f"Certificate verification failed: {e}"}
    except Exception as e:
        return {"url": url, "ssl": False, "error": str(e)}


def _discover_paths_impl(url: str, paths: list) -> dict:
    """Discover accessible paths on a web server."""
    if not _HAS_REQUESTS:
        return {"error": "requests library not available"}
    base = url.rstrip("/")
    found = []
    errors = 0
    session = requests.Session()
    session.headers["User-Agent"] = "RedTeam-MCP-SecurityScanner/2.0"

    for path in paths:
        try:
            resp = session.get(f"{base}{path}", timeout=5, allow_redirects=False)
            if resp.status_code < 400:
                found.append({
                    "path": path,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "content_type": resp.headers.get("Content-Type", ""),
                })
        except Exception:
            errors += 1

    return {
        "url": base,
        "paths_tested": len(paths),
        "paths_found": len(found),
        "errors": errors,
        "results": found,
    }


def _check_http_methods(url: str) -> dict:
    """Test which HTTP methods are allowed."""
    if not _HAS_REQUESTS:
        return {"error": "requests library not available"}
    allowed = []
    for method in _HTTP_METHODS:
        try:
            resp = requests.request(method, url, timeout=5, allow_redirects=False,
                                    headers={"User-Agent": "RedTeam-MCP-SecurityScanner/2.0"})
            if resp.status_code < 500 and resp.status_code != 405:
                allowed.append({"method": method, "status": resp.status_code})
        except Exception:
            pass
    dangerous = [m for m in allowed if m["method"] in ("TRACE", "PUT", "DELETE", "CONNECT")]
    return {"url": url, "allowed_methods": allowed, "dangerous_methods": dangerous}


def _check_cors(url: str) -> dict:
    """Check for CORS misconfiguration."""
    if not _HAS_REQUESTS:
        return {"error": "requests library not available"}
    results = {}
    test_origins = ["https://evil.com", "null", url]
    for origin in test_origins:
        try:
            resp = requests.get(url, timeout=5, headers={
                "Origin": origin,
                "User-Agent": "RedTeam-MCP-SecurityScanner/2.0",
            })
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao:
                results[origin] = {
                    "allow_origin": acao,
                    "allow_credentials": acac,
                    "vulnerable": acao == "*" or (acao == origin and origin == "https://evil.com"),
                }
        except Exception:
            pass
    vulnerable = any(v.get("vulnerable") for v in results.values())
    return {"url": url, "cors_tests": results, "vulnerable": vulnerable}


def _check_server_disclosure(url: str) -> dict:
    """Check for server information disclosure."""
    if not _HAS_REQUESTS:
        return {"error": "requests library not available"}
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "RedTeam-MCP-SecurityScanner/2.0"})
        disclosed = {}
        for h in _DISCLOSURE_HEADERS:
            val = resp.headers.get(h)
            if val:
                disclosed[h] = val
        return {"url": url, "disclosed_headers": disclosed, "disclosure_count": len(disclosed)}
    except Exception as e:
        return {"url": url, "error": str(e)}


def _check_open_redirects(url: str) -> dict:
    """Check for open redirect vulnerabilities on common parameters."""
    if not _HAS_REQUESTS:
        return {"error": "requests library not available"}
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    evil = "https://evil.com"
    vulnerable = []

    for param in _REDIRECT_PARAMS:
        test_url = f"{base}?{param}={evil}"
        try:
            resp = requests.get(test_url, timeout=5, allow_redirects=False,
                                headers={"User-Agent": "RedTeam-MCP-SecurityScanner/2.0"})
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    vulnerable.append({"param": param, "redirect_to": location, "status": resp.status_code})
        except Exception:
            pass
    return {"url": url, "tested_params": len(_REDIRECT_PARAMS), "vulnerable_params": vulnerable}


def _check_injection_points(url: str) -> dict:
    """Basic injection point detection — test parameters for reflection."""
    if not _HAS_REQUESTS:
        return {"error": "requests library not available"}
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    canary = "rtmcp7x3q"
    reflections = []

    # Test existing query params
    for param_name in params:
        test_params = {**{k: v[0] for k, v in params.items()}, param_name: canary}
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
        try:
            resp = requests.get(test_url, timeout=5,
                                headers={"User-Agent": "RedTeam-MCP-SecurityScanner/2.0"})
            if canary in resp.text:
                reflections.append({"param": param_name, "reflected": True, "context": "response body"})
        except Exception:
            pass

    # Test common params if none in URL
    if not params:
        for param_name in ["q", "search", "query", "id", "name", "page", "input", "data"]:
            test_url = f"{url}{'&' if '?' in url else '?'}{param_name}={canary}"
            try:
                resp = requests.get(test_url, timeout=5,
                                    headers={"User-Agent": "RedTeam-MCP-SecurityScanner/2.0"})
                if canary in resp.text:
                    reflections.append({"param": param_name, "reflected": True, "context": "response body"})
            except Exception:
                pass

    return {"url": url, "reflections": reflections, "potential_xss_points": len(reflections)}


# ═══════════════════════════════════════════════════════════════
# MCP TOOLS
# ═══════════════════════════════════════════════════════════════

app_mcp = FastMCP("RedTeam MCP Server")


@app_mcp.tool()
def simulate_attack(query: str, project: str = "", dry_run: bool = False) -> str:
    """Simulate an attack using natural language. Resolves your description to real attack techniques and executes them.
    Examples: 'steal credentials', 'disable logging', 'create backdoor', 'full attack chain', 'T1059.001', 'gcp.persistence.create-admin-service-account'
    Set dry_run=True to see what would run without executing. Auto-generates an executive report after execution."""
    techniques = resolve_techniques(query)
    if not techniques:
        return json.dumps({
            "error": "No matching techniques found",
            "query": query,
            "hint": "Try: 'steal credentials', 'disable logging', 'lateral movement', 'purple team', or a specific ID like 'gcp.persistence.create-admin-service-account'"
        })

    target_project = project or GCP_PROJECT
    results = []

    for tid in techniques:
        tech_info = STRATUS_TECHNIQUES.get(tid) or ATOMIC_TECHNIQUES.get(tid)
        if dry_run:
            results.append({
                "technique": tid,
                "name": tech_info.get("name", tid) if tech_info else tid,
                "engine": tech_info.get("engine", "unknown") if tech_info else "unknown",
                "dry_run": True,
                "would_execute": True,
            })
            continue

        if tid.startswith("gcp.") or tid.startswith("aws.") or tid.startswith("azure."):
            results.append(_run_stratus(tid, action="detonate", project=target_project))
        elif tid.startswith("T"):
            results.append(_run_atomic(tid))
        else:
            results.append({"technique": tid, "error": "Unknown engine for technique", "success": False})

    output = {
        "query": query,
        "project": target_project,
        "techniques_matched": len(techniques),
        "results": results,
    }

    # Auto-generate executive report for non-dry-run executions
    if not dry_run and results:
        report = _build_report(query, results, target_project)
        output["report_id"] = report["id"]
        output["report"] = report["markdown"]

    return json.dumps(output)


@app_mcp.tool()
def generate_report(results_json: str = "", query: str = "manual report", project: str = "") -> str:
    """Generate a purple team executive report from attack results.
    Pass results_json as a JSON array of execution results, or leave empty to report on the last simulation.
    Returns a comprehensive markdown report with MITRE ATT&CK coverage, detection gaps, and remediation."""
    target_project = project or GCP_PROJECT

    if results_json:
        try:
            results = json.loads(results_json)
            if not isinstance(results, list):
                results = [results]
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON in results_json"})
    else:
        # Use the most recent report's raw results, or return error
        if REPORTS_STORE:
            return json.dumps({"report_id": REPORTS_STORE[-1]["id"], "report": REPORTS_STORE[-1]["markdown"]})
        return json.dumps({"error": "No results provided and no previous simulations found"})

    report = _build_report(query, results, target_project)
    return json.dumps({"report_id": report["id"], "report": report["markdown"]})


@app_mcp.tool()
def submit_results(results_json: str, query: str = "remote submission", project: str = "") -> str:
    """Submit attack results from a remote/local agent and generate a report.
    Use this when the local CLI (stratus/atomic) sends results back to the cloud instance.
    results_json should be a JSON array of execution result objects."""
    target_project = project or GCP_PROJECT
    try:
        results = json.loads(results_json)
        if not isinstance(results, list):
            results = [results]
    except json.JSONDecodeError:
        return json.dumps({"error": "Invalid JSON in results_json"})

    report = _build_report(query, results, target_project)
    return json.dumps({
        "report_id": report["id"],
        "techniques_processed": len(results),
        "report": report["markdown"],
    })


@app_mcp.tool()
def list_attacks(platform: str = "all", tactic: str = "") -> str:
    """List available attack techniques. Filter by platform (gcp/linux/windows/all) or MITRE tactic (persistence/credential-access/etc)."""
    results = []
    tactic_lower = tactic.lower()

    if platform in ["gcp", "cloud", "all"]:
        for tid, tech in STRATUS_TECHNIQUES.items():
            if tactic_lower and tactic_lower not in tech.get("tactic", "").lower():
                continue
            results.append(tech)

    if platform in ["linux", "windows", "endpoint", "all"]:
        for tid, tech in ATOMIC_TECHNIQUES.items():
            if tactic_lower and tactic_lower not in tech.get("name", "").lower():
                continue
            if platform != "all" and platform not in tech.get("platforms", []):
                continue
            results.append(tech)

    return json.dumps({"count": len(results), "techniques": results[:100]})


@app_mcp.tool()
def attack_info(technique_id: str) -> str:
    """Get detailed information about a specific attack technique."""
    if technique_id.startswith("gcp.") or technique_id.startswith("aws.") or technique_id.startswith("azure."):
        try:
            result = subprocess.run([STRATUS_BIN, "show", technique_id], capture_output=True, text=True, timeout=10)
            tech = STRATUS_TECHNIQUES.get(technique_id, {})
            return json.dumps({
                "id": technique_id,
                "name": tech.get("name", technique_id),
                "engine": "stratus",
                "tactic": tech.get("tactic", ""),
                "description": result.stdout[:2000] if result.stdout else "No description available",
            })
        except Exception as e:
            return json.dumps({"error": str(e)})

    elif technique_id.startswith("T"):
        tech = ATOMIC_TECHNIQUES.get(technique_id)
        if not tech:
            return json.dumps({"error": f"Technique {technique_id} not found"})

        yaml_file = os.path.join(ATOMICS_PATH, technique_id, f"{technique_id}.yaml")
        details = {"id": technique_id, "name": tech["name"], "engine": "atomic", "platforms": tech["platforms"], "test_count": tech["test_count"]}
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            tests = data.get("atomic_tests", [])
            details["tests"] = [{"name": t.get("name"), "platforms": t.get("supported_platforms", []),
                                  "description": t.get("description", "")[:300]} for t in tests[:10]]
        except:
            pass
        return json.dumps(details)

    return json.dumps({"error": f"Unknown technique format: {technique_id}"})


@app_mcp.tool()
def cleanup_attack(technique_id: str, project: str = "") -> str:
    """Clean up / revert a Stratus Red Team attack technique. Removes any infrastructure or config changes made during detonation."""
    if not technique_id.startswith("gcp."):
        return json.dumps({"error": "Cleanup only supported for Stratus (gcp.*) techniques"})
    result = _run_stratus(technique_id, action="cleanup", project=project or GCP_PROJECT)
    return json.dumps(result)


@app_mcp.tool()
def warmup_attack(technique_id: str, project: str = "") -> str:
    """Warm up a Stratus attack technique — spins up prerequisite infrastructure without detonating the attack."""
    if not technique_id.startswith("gcp."):
        return json.dumps({"error": "Warmup only supported for Stratus (gcp.*) techniques"})
    result = _run_stratus(technique_id, action="warmup", project=project or GCP_PROJECT)
    return json.dumps(result)


@app_mcp.tool()
def attack_status() -> str:
    """Show the status of all Stratus Red Team techniques (COLD/WARM/DETONATED)."""
    try:
        env = os.environ.copy()
        env["GOOGLE_PROJECT"] = GCP_PROJECT
        result = subprocess.run([STRATUS_BIN, "status"], capture_output=True, text=True, timeout=10, env=env)
        statuses = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("gcp."):
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 3:
                    statuses.append({"id": parts[0], "name": parts[1], "status": parts[-1]})
        return json.dumps({"techniques": statuses, "count": len(statuses)})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def attack_log(last_n: int = 10) -> str:
    """View the log of recent attack simulations."""
    try:
        log_files = sorted(glob.glob(os.path.join(LOG_DIR, "*.json")), reverse=True)[:last_n]
        logs = []
        for lf in log_files:
            with open(lf) as f:
                logs.append(json.load(f))
        return json.dumps({"count": len(logs), "logs": logs})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def resolve_attack_query(query: str) -> str:
    """Preview which attack techniques would be matched for a natural language query without executing anything."""
    techniques = resolve_techniques(query)
    details = []
    for tid in techniques:
        tech = STRATUS_TECHNIQUES.get(tid) or ATOMIC_TECHNIQUES.get(tid)
        details.append({
            "id": tid,
            "name": tech.get("name", tid) if tech else tid,
            "engine": tech.get("engine", "unknown") if tech else "unknown",
        })
    return json.dumps({"query": query, "matched": len(details), "techniques": details})


# ═══════════════════════════════════════════════════════════════
# WEB APP PENTESTING MCP TOOLS
# ═══════════════════════════════════════════════════════════════

@app_mcp.tool()
def scan_web_app(url: str, scan_type: str = "full") -> str:
    """Scan a web application for security vulnerabilities.
    scan_type: 'full' (all checks), 'quick' (headers + SSL + disclosure only), 'paths' (path discovery only).
    Checks: security headers, SSL/TLS, path discovery, HTTP methods, CORS, server disclosure, open redirects, injection points."""
    if not _HAS_REQUESTS:
        return json.dumps({"error": "requests library not installed — run: pip install requests"})

    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"

    scan_results = {"url": url, "scan_type": scan_type, "timestamp": datetime.now(timezone.utc).isoformat(), "findings": {}}

    # Always run these
    scan_results["findings"]["security_headers"] = _check_security_headers(url)
    scan_results["findings"]["ssl_tls"] = _check_ssl(url)
    scan_results["findings"]["server_disclosure"] = _check_server_disclosure(url)

    if scan_type in ("full", "paths"):
        scan_results["findings"]["path_discovery"] = _discover_paths_impl(url, _COMMON_PATHS)

    if scan_type == "full":
        scan_results["findings"]["http_methods"] = _check_http_methods(url)
        scan_results["findings"]["cors"] = _check_cors(url)
        scan_results["findings"]["open_redirects"] = _check_open_redirects(url)
        scan_results["findings"]["injection_points"] = _check_injection_points(url)

    # Compute overall risk
    risks = []
    hdr = scan_results["findings"].get("security_headers", {})
    if hdr.get("score", 100) < 50:
        risks.append("Poor security headers coverage")
    ssl_info = scan_results["findings"].get("ssl_tls", {})
    if ssl_info.get("valid") is False:
        risks.append("Invalid SSL/TLS certificate")
    cors_info = scan_results["findings"].get("cors", {})
    if cors_info.get("vulnerable"):
        risks.append("CORS misconfiguration detected")
    paths = scan_results["findings"].get("path_discovery", {})
    sensitive = [p for p in paths.get("results", []) if any(s in p.get("path", "") for s in [".env", ".git", "admin", "debug", "actuator"])]
    if sensitive:
        risks.append(f"{len(sensitive)} sensitive paths exposed")
    redirects = scan_results["findings"].get("open_redirects", {})
    if redirects.get("vulnerable_params"):
        risks.append("Open redirect vulnerability")
    injection = scan_results["findings"].get("injection_points", {})
    if injection.get("potential_xss_points", 0) > 0:
        risks.append("Parameter reflection detected (potential XSS)")
    methods = scan_results["findings"].get("http_methods", {})
    if methods.get("dangerous_methods"):
        risks.append(f"Dangerous HTTP methods enabled: {', '.join(m['method'] for m in methods['dangerous_methods'])}")
    disclosure = scan_results["findings"].get("server_disclosure", {})
    if disclosure.get("disclosure_count", 0) > 0:
        risks.append("Server information disclosure")

    scan_results["risk_summary"] = risks
    scan_results["risk_level"] = "CRITICAL" if len(risks) >= 5 else "HIGH" if len(risks) >= 3 else "MEDIUM" if len(risks) >= 1 else "LOW"

    return json.dumps(scan_results)


@app_mcp.tool()
def check_headers(url: str) -> str:
    """Focused HTTP security headers audit for a URL.
    Checks: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and more."""
    if not _HAS_REQUESTS:
        return json.dumps({"error": "requests library not installed — run: pip install requests"})
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
    result = _check_security_headers(url)
    result["disclosure"] = _check_server_disclosure(url)
    return json.dumps(result)


@app_mcp.tool()
def discover_paths(url: str, wordlist: str = "common") -> str:
    """Path/directory enumeration on a web server.
    wordlist: 'common' (~50 paths) or 'extended' (~90 paths).
    Discovers admin panels, API endpoints, config files, backup files, debug endpoints, etc."""
    if not _HAS_REQUESTS:
        return json.dumps({"error": "requests library not installed — run: pip install requests"})
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
    paths = _EXTENDED_PATHS if wordlist == "extended" else _COMMON_PATHS
    return json.dumps(_discover_paths_impl(url, paths))


# ═══════════════════════════════════════════════════════════════
# FASTAPI WEB SERVER + MCP SSE
# ═══════════════════════════════════════════════════════════════

app = FastAPI(title="RedTeam MCP Server")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "stratus_techniques": len(STRATUS_TECHNIQUES),
        "atomic_techniques": len(ATOMIC_TECHNIQUES),
        "gcp_project": GCP_PROJECT,
        "reports_count": len(REPORTS_STORE),
        "web_scanning": _HAS_REQUESTS,
    }


@app.get("/", response_class=HTMLResponse)
async def index():
    return open(os.path.join(os.path.dirname(__file__), "static", "index.html")).read()


# ═══════════════════════════════════════════════════════════════
# REPORT API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.post("/api/report")
async def api_generate_report(request: Request):
    """Accept attack results from a local agent and generate a report."""
    body = await request.json()
    results = body.get("results", [])
    query = body.get("query", "remote agent submission")
    project = body.get("project", GCP_PROJECT)

    if not results:
        return JSONResponse({"error": "No results provided"}, status_code=400)

    report = _build_report(query, results, project)
    return JSONResponse({
        "report_id": report["id"],
        "timestamp": report["timestamp"],
        "threat_level": report["threat_level"],
        "posture_score": report["posture_score"],
        "report": report["markdown"],
    })


@app.post("/api/results")
async def api_submit_results(request: Request):
    """Accept raw execution results and store them, generating a report."""
    body = await request.json()
    results = body.get("results", [])
    query = body.get("query", "result submission")
    project = body.get("project", GCP_PROJECT)

    if not results:
        return JSONResponse({"error": "No results provided"}, status_code=400)

    report = _build_report(query, results, project)
    return JSONResponse({
        "report_id": report["id"],
        "timestamp": report["timestamp"],
        "techniques_stored": len(results),
        "report_generated": True,
    })


@app.get("/api/reports")
async def api_list_reports():
    """List all generated reports."""
    summaries = []
    for r in reversed(REPORTS_STORE):
        summaries.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "query": r["query"],
            "project": r["project"],
            "threat_level": r["threat_level"],
            "posture_score": r["posture_score"],
            "total_techniques": r["total_techniques"],
            "gaps": len(r["gaps"]),
        })
    return JSONResponse({"count": len(summaries), "reports": summaries})


@app.get("/api/reports/{report_id}")
async def api_get_report(report_id: str):
    """Retrieve a specific report by ID."""
    for r in REPORTS_STORE:
        if r["id"] == report_id:
            return JSONResponse({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "query": r["query"],
                "project": r["project"],
                "threat_level": r["threat_level"],
                "posture_score": r["posture_score"],
                "total_techniques": r["total_techniques"],
                "gaps": len(r["gaps"]),
                "markdown": r["markdown"],
                "technique_rows": r["technique_rows"],
            })
    return JSONResponse({"error": "Report not found"}, status_code=404)


# Mount MCP SSE endpoint
mcp_app = app_mcp.sse_app()
app.mount("/mcp", mcp_app)
app.mount("/sse", mcp_app)


# ═══════════════════════════════════════════════════════════════
# CHAT ENDPOINT
# ═══════════════════════════════════════════════════════════════

@app.post("/api/chat")
async def chat(request: Request):
    """Natural language chat endpoint that resolves queries to attacks."""
    body = await request.json()
    message = body.get("message", "").strip()
    if not message:
        return JSONResponse({"error": "No message provided"})

    msg_lower = message.lower()

    # Web scanning intents
    if any(w in msg_lower for w in ["scan web", "scan http", "scan url", "check headers", "pentest", "web vuln", "web app"]):
        # Extract URL from message
        url_match = re.search(r'https?://[^\s<>"]+|www\.[^\s<>"]+', message)
        if url_match:
            target_url = url_match.group(0)
            if "header" in msg_lower:
                result = json.loads(check_headers(target_url))
                return JSONResponse({"response": f"Security headers audit for {target_url}", "type": "web_scan", "results": result})
            elif "path" in msg_lower or "discover" in msg_lower or "dir" in msg_lower:
                result = json.loads(discover_paths(target_url))
                return JSONResponse({"response": f"Path discovery for {target_url}", "type": "web_scan", "results": result})
            else:
                result = json.loads(scan_web_app(target_url))
                return JSONResponse({"response": f"Full web app scan for {target_url}", "type": "web_scan", "results": result})
        return JSONResponse({"response": "Please provide a URL to scan. Example: 'scan web app https://example.com'"})

    # Report intents
    if any(w in msg_lower for w in ["report", "reports"]):
        if "list" in msg_lower or "show" in msg_lower or "all" in msg_lower:
            summaries = [{"id": r["id"], "timestamp": r["timestamp"], "query": r["query"],
                          "threat_level": r["threat_level"], "posture_score": r["posture_score"]}
                         for r in reversed(REPORTS_STORE)]
            return JSONResponse({"response": f"{len(summaries)} reports available", "type": "reports_list", "reports": summaries})
        if REPORTS_STORE:
            latest = REPORTS_STORE[-1]
            return JSONResponse({"response": "Latest report", "type": "report", "report": latest["markdown"],
                                 "report_id": latest["id"], "threat_level": latest["threat_level"]})
        return JSONResponse({"response": "No reports generated yet. Run an attack simulation first."})

    if any(w in msg_lower for w in ["list", "show", "what attacks", "available"]):
        platform = "gcp" if "gcp" in msg_lower or "cloud" in msg_lower else "all"
        techniques = resolve_techniques(message) if not any(w in msg_lower for w in ["all", "list all"]) else []
        if techniques:
            details = []
            for tid in techniques:
                tech = STRATUS_TECHNIQUES.get(tid) or ATOMIC_TECHNIQUES.get(tid)
                details.append({"id": tid, "name": tech.get("name", tid) if tech else tid})
            return JSONResponse({"response": f"Found {len(details)} matching techniques", "techniques": details})
        all_tech = list(STRATUS_TECHNIQUES.values()) + list(ATOMIC_TECHNIQUES.values())[:50]
        return JSONResponse({"response": f"{len(all_tech)} techniques available", "techniques": all_tech})

    if any(w in msg_lower for w in ["simulate", "attack", "run", "execute", "detonate", "test", "inject"]):
        dry_run = "dry" in msg_lower or "preview" in msg_lower or "plan" in msg_lower
        techniques = resolve_techniques(message)
        if not techniques:
            return JSONResponse({"response": "No matching techniques found. Try: 'simulate credential theft', 'attack persistence', 'run lateral movement'", "techniques_matched": 0})

        results = []
        for tid in techniques:
            tech = STRATUS_TECHNIQUES.get(tid) or ATOMIC_TECHNIQUES.get(tid)
            if dry_run:
                results.append({"id": tid, "name": tech.get("name", tid) if tech else tid, "dry_run": True})
            else:
                if tid.startswith("gcp."):
                    results.append(_run_stratus(tid, action="detonate", project=GCP_PROJECT))
                elif tid.startswith("T"):
                    results.append(_run_atomic(tid))

        response = {"response": f"{'Planned' if dry_run else 'Executed'} {len(results)} attack techniques", "results": results}

        # Auto-generate report for non-dry-run
        if not dry_run and results:
            report = _build_report(message, results, GCP_PROJECT)
            response["type"] = "attack_with_report"
            response["report"] = report["markdown"]
            response["report_id"] = report["id"]
            response["threat_level"] = report["threat_level"]

        return JSONResponse(response)

    if any(w in msg_lower for w in ["cleanup", "revert", "undo"]):
        techniques = resolve_techniques(message)
        results = [_run_stratus(tid, action="cleanup") for tid in techniques if tid.startswith("gcp.")]
        return JSONResponse({"response": f"Cleaned up {len(results)} techniques", "results": results})

    if any(w in msg_lower for w in ["status", "state"]):
        return JSONResponse(json.loads(attack_status()))

    # Default: try to resolve as an attack query
    techniques = resolve_techniques(message)
    if techniques:
        details = [{"id": tid, "name": (STRATUS_TECHNIQUES.get(tid) or ATOMIC_TECHNIQUES.get(tid, {})).get("name", tid)} for tid in techniques]
        return JSONResponse({
            "response": f"Matched {len(details)} techniques for '{message}'. Say 'simulate {message}' to execute.",
            "techniques": details
        })

    return JSONResponse({"response": "I didn't understand that. Try: 'simulate credential theft', 'list gcp attacks', 'scan web app https://example.com', 'show reports'"})


if __name__ == "__main__":
    import uvicorn
    logger.info(f"RedTeam MCP Server v2.0 starting on port {PORT}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
