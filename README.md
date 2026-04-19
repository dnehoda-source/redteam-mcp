# Red Team MCP Server

An AI-powered red team assistant that understands natural language, executes offensive security operations, and maintains session history — all through a browser UI backed by Gemini tool orchestration.

## What It Does

Traditional red team tooling requires knowing exact commands, flags, and syntax. This server lets you describe what you want to do in plain English and routes it to the appropriate security tool or scan automatically.

Ask it to *"check for SQL injection on this login form"* or *"scan for IAM privilege escalation in my GCP project"* — Gemini interprets the intent and calls the right tool. Results are tracked in session history so you can build on previous findings without losing context.

## Why You Need It

- **Natural language routing** — no need to remember tool syntax; describe the objective
- **Session continuity** — chat history and command history persist across the conversation so the AI has full context of your engagement
- **Exploitation coverage** — SQLi, XSS, SSTI, SSRF, auth bypass, IAM escalation, API security testing in one place
- **MCP-compatible** — tools are exposed as MCP endpoints, usable by Claude or any MCP client

## Tools

| Tool | Description |
|------|-------------|
| `exploit_web_vulnerabilities` | Tests for SQLi, XSS, SSTI, command injection, path traversal, open redirect |
| `exploit_ssrf` | SSRF probes targeting GCP/AWS/Azure metadata endpoints |
| `exploit_authentication` | Default credential testing, JWT none-algorithm bypass |
| `exploit_cloud_iam` | GCP IAM misconfiguration scanner |
| `exploit_api_security` | IDOR, mass assignment, HTTP verb tampering, rate limit bypass |

## Architecture

```
Browser UI ──► FastAPI Server ──► Gemini (NL → tool routing)
                    │
                    └──► MCP Tools (exploitation modules)
                    │
                    └──► Session Store (chat + command history)
```

## Prerequisites

- Google Cloud project with Vertex AI enabled
- Application Default Credentials
- Python 3.11+

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECOPS_PROJECT_ID` | Yes | GCP project ID (used for Vertex AI) |
| `GEMINI_MODEL` | No | Gemini model (default: `gemini-2.5-flash`) |
| `OAUTH_CLIENT_ID` | No | Google OAuth client ID — if set, login required |
| `ALLOWED_EMAILS` | No | Comma-separated list of allowed Google emails |
| `PORT` | No | HTTP port (default: `8080`) |

## Deploy to Cloud Run

```bash
git clone https://github.com/dnehoda-source/redteam-mcp.git
cd redteam-mcp

# Build and push image
gcloud builds submit --tag gcr.io/YOUR_PROJECT/redteam-mcp:latest .

# Deploy
gcloud run deploy redteam-mcp \
  --image gcr.io/YOUR_PROJECT/redteam-mcp:latest \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --memory 512Mi \
  --set-env-vars "SECOPS_PROJECT_ID=YOUR_PROJECT"
```

## Run Locally

```bash
git clone https://github.com/dnehoda-source/redteam-mcp.git
cd redteam-mcp

pip install -r requirements.txt

# Authenticate with Google
gcloud auth application-default login

export SECOPS_PROJECT_ID=your-project

python3 main.py
```

Open `http://localhost:8080`

## Usage

### Natural Language Chat

Type objectives directly — Gemini routes to the appropriate tool:

```
"Test login.example.com for SQL injection"
→ exploit_web_vulnerabilities(url="https://login.example.com", vuln_types="sqli")

"Check for SSRF via the URL parameter on /api/fetch"
→ exploit_ssrf(url="https://target.com/api/fetch", param="url")

"Scan GCP project acme-prod for IAM privilege escalation paths"
→ exploit_cloud_iam(project_id="acme-prod")
```

### Command History

All tool calls are logged in the sidebar. Click any previous command to replay it.

### Session Memory

The AI maintains chat context within a session — reference earlier findings without repeating yourself:

```
"Run SQLi tests on that endpoint we found earlier"
"Now try SSRF on the same target"
```

## Security

- Intended for authorized penetration testing, CTF competitions, and security research
- Security headers on all responses (CSP, HSTS, X-Frame-Options, etc.)
- Optional Google OAuth — set `OAUTH_CLIENT_ID` to restrict access to specific accounts
- No results are stored persistently — session history is in-memory only

## Adding OAuth Protection

```bash
# Create OAuth client at console.cloud.google.com → APIs & Services → Credentials
# Add your Cloud Run URL as an authorized JavaScript origin

gcloud run services update redteam-mcp \
  --region us-central1 \
  --update-env-vars "OAUTH_CLIENT_ID=YOUR_CLIENT_ID,ALLOWED_EMAILS=you@example.com"
```
