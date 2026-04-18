"""
RedTeam MCP Server — Natural Language Attack Simulation Platform
Integrates Stratus Red Team (cloud) + Atomic Red Team (endpoint) behind MCP.
"""

import json
import os
import subprocess
import yaml
import glob
import re
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from mcp.server.fastmcp import FastMCP

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
            # Table rows are: | TECHNIQUE_ID | NAME | PLATFORM | TACTIC |
            if "|" not in line or "---" in line or "TECHNIQUE ID" in line:
                continue
            parts = [p.strip() for p in line.split("|")]
            parts = [p for p in parts if p]  # remove empty from leading/trailing |
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

    # 1. Direct technique ID match (e.g., "T1059.001" or "gcp.persistence.create-admin-service-account")
    if re.match(r"^(gcp\.|aws\.|azure\.|T\d{4})", query_lower):
        return [query_lower]

    # 2. Alias match
    for alias, technique_ids in ATTACK_ALIASES.items():
        if alias in query_lower or query_lower in alias:
            matched.extend(technique_ids)

    # 3. MITRE tactic match
    for tactic_name, tactic_key in TACTIC_MAP.items():
        if tactic_name in query_lower:
            # Return all Stratus techniques for this tactic
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
        # Log the execution
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
        # Filter to platform-compatible tests
        compatible = [t for t in tests if platform in t.get("supported_platforms", [])]
        if not compatible:
            return {"engine": "atomic", "technique": technique_id, "error": f"No {platform}-compatible tests found", "success": False,
                    "available_platforms": list(set(p for t in tests for p in t.get("supported_platforms", [])))}

        test = compatible[min(test_index, len(compatible) - 1)]
        executor = test.get("executor", {})
        command = executor.get("command", "")
        executor_name = executor.get("name", "sh")

        # Substitute default input arguments
        for arg_name, arg_def in test.get("input_arguments", {}).items():
            default_val = str(arg_def.get("default", ""))
            command = command.replace(f"#{{{arg_name}}}", default_val)

        # Replace PathToAtomicsFolder
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

        # Execute the command
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

        # Log
        log_file = os.path.join(LOG_DIR, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{technique_id}.json")
        with open(log_file, "w") as f:
            json.dump(output, f, indent=2)

        return output

    except subprocess.TimeoutExpired:
        return {"engine": "atomic", "technique": technique_id, "error": "Execution timed out (120s)", "success": False}
    except Exception as e:
        return {"engine": "atomic", "technique": technique_id, "error": str(e), "success": False}


# ═══════════════════════════════════════════════════════════════
# MCP TOOLS
# ═══════════════════════════════════════════════════════════════

app_mcp = FastMCP("RedTeam MCP Server")


@app_mcp.tool()
def simulate_attack(query: str, project: str = "", dry_run: bool = False) -> str:
    """Simulate an attack using natural language. Resolves your description to real attack techniques and executes them.
    Examples: 'steal credentials', 'disable logging', 'create backdoor', 'full attack chain', 'T1059.001', 'gcp.persistence.create-admin-service-account'
    Set dry_run=True to see what would run without executing."""
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

    return json.dumps({
        "query": query,
        "project": target_project,
        "techniques_matched": len(techniques),
        "results": results,
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
        # Parse status output
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
# FASTAPI WEB SERVER + MCP SSE
# ═══════════════════════════════════════════════════════════════

app = FastAPI(title="RedTeam MCP Server")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "stratus_techniques": len(STRATUS_TECHNIQUES),
        "atomic_techniques": len(ATOMIC_TECHNIQUES),
        "gcp_project": GCP_PROJECT,
    }


@app.get("/", response_class=HTMLResponse)
async def index():
    return open(os.path.join(os.path.dirname(__file__), "static", "index.html")).read()


# Mount MCP SSE endpoint
mcp_app = app_mcp.sse_app()
app.mount("/mcp", mcp_app)
app.mount("/sse", mcp_app)


# ═══════════════════════════════════════════════════════════════
# CHAT ENDPOINT (like MCP Boss)
# ═══════════════════════════════════════════════════════════════

@app.post("/api/chat")
async def chat(request: Request):
    """Natural language chat endpoint that resolves queries to attacks."""
    body = await request.json()
    message = body.get("message", "").strip()
    if not message:
        return JSONResponse({"error": "No message provided"})

    # Simple intent detection
    msg_lower = message.lower()

    if any(w in msg_lower for w in ["list", "show", "what attacks", "available"]):
        platform = "gcp" if "gcp" in msg_lower or "cloud" in msg_lower else "all"
        techniques = resolve_techniques(message) if not any(w in msg_lower for w in ["all", "list all"]) else []
        if techniques:
            details = []
            for tid in techniques:
                tech = STRATUS_TECHNIQUES.get(tid) or ATOMIC_TECHNIQUES.get(tid)
                details.append({"id": tid, "name": tech.get("name", tid) if tech else tid})
            return JSONResponse({"response": f"Found {len(details)} matching techniques", "techniques": details})
        # List all
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
        return JSONResponse({"response": f"{'Planned' if dry_run else 'Executed'} {len(results)} attack techniques", "results": results})

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

    return JSONResponse({"response": "I didn't understand that. Try: 'simulate credential theft', 'list gcp attacks', 'attack info gcp.persistence.create-admin-service-account'"})


if __name__ == "__main__":
    import uvicorn
    logger.info(f"RedTeam MCP Server starting on port {PORT}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
