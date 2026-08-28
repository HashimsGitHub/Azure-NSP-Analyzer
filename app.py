from flask import Flask, jsonify
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
import datetime
import traceback
import re
import html
import json
import os

app = Flask(__name__)

# Read from environment variable - required for running
WORKSPACE_ID = os.getenv('LOG_ANALYTICS_WORKSPACE_ID')
if not WORKSPACE_ID:
    raise ValueError("LOG_ANALYTICS_WORKSPACE_ID environment variable is not set")

WORKSPACE_NAME = os.getenv('WORKSPACE_NAME', 'law-nsp-poc')
NSP_SERVICE_TAG = os.getenv('NSP_SERVICE_TAG', 'ContainerAppsManagement.AustraliaEast')

QUERY = """
Syslog
| where TimeGenerated > ago(24h)
| order by TimeGenerated desc
| take 5
""".strip()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def html_escape(value):
    return html.escape(str(value or ""))


def extract_source_ip(error_text):
    """
    Extract source IP from NSP error message.

    Example:
    Access to workspace 'law-nsp-poc' from '20.11.107.220' is denied
    """

    patterns = [
        r"from '([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'",
        r"from \"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\"",
        r"from\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
    ]

    for pattern in patterns:
        match = re.search(pattern, error_text)

        if match:
            return match.group(1)

    return "Unknown"


def extract_nsp_error(error_text):
    """
    Extract the NSP-specific error from Azure's nested error response.
    """

    nsp_code = "NspValidationFailedError"

    if nsp_code not in error_text:
        return {
            "code": "Unknown",
            "message": "Network Security Perimeter validation failed."
        }

    match = re.search(
        r'"code":\s*"NspValidationFailedError",\s*"message":\s*"([^"]+)"',
        error_text
    )

    if match:
        return {
            "code": nsp_code,
            "message": match.group(1)
        }

    return {
        "code": nsp_code,
        "message": "Access was denied by Network Security Perimeter validation."
    }


def get_logs():
    credential = DefaultAzureCredential()

    client = LogsQueryClient(credential)

    result = client.query_workspace(
        workspace_id=WORKSPACE_ID,
        query=QUERY,
        timespan=datetime.timedelta(days=1)
    )

    records = []

    table_count = len(result.tables)

    if table_count == 0:
        return records, 0

    table = result.tables[0]

    column_names = []

    for column in table.columns:
        try:
            column_names.append(column.name)
        except Exception:
            column_names.append(str(column))

    for row in table.rows:

        record = {}

        for index, column_name in enumerate(column_names):
            try:
                value = row[index]
            except Exception:
                value = ""

            record[column_name] = str(value)

        records.append(record)

    return records, table_count


def build_allowed_page(records, table_count):

    row_count = len(records)
    timestamp = utc_now().isoformat()

    records_json = json.dumps(records, indent=2)

    rows_html = ""

    for index, record in enumerate(records):

        severity = record.get("SeverityLevel", "info")

        severity_class = {
            "info": "severity-info",
            "warning": "severity-warning",
            "error": "severity-error",
            "critical": "severity-critical"
        }.get(severity.lower(), "severity-info")

        message = record.get("SyslogMessage", "")

        short_message = message

        if len(short_message) > 160:
            short_message = short_message[:160] + "..."

        rows_html += f"""
        <tr data-search="{html_escape(json.dumps(record).lower())}">
            <td>
                <span class="time">
                    {html_escape(record.get("TimeGenerated", ""))}
                </span>
            </td>

            <td>
                <div class="host">
                    <div class="host-icon">VM</div>
                    <div>
                        <strong>{html_escape(record.get("Computer", "Unknown"))}</strong>
                        <small>{html_escape(record.get("HostIP", ""))}</small>
                    </div>
                </div>
            </td>

            <td>
                <span class="process">
                    {html_escape(record.get("ProcessName", ""))}
                </span>
            </td>

            <td>
                <span class="severity {severity_class}">
                    {html_escape(severity.upper())}
                </span>
            </td>

            <td class="message-cell">
                {html_escape(short_message)}
            </td>

            <td>
                <button
                    class="details-btn"
                    onclick='showRecord({json.dumps(record)})'>
                    View
                </button>
            </td>
        </tr>
        """

    return f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Azure NSP Security Dashboard</title>

<style>

:root {{
    --bg: #07111f;
    --bg-secondary: #0b1628;
    --panel: #0f1c2e;
    --panel-light: #13243a;
    --border: #20334d;

    --text: #f8fafc;
    --muted: #8fa3bb;

    --azure: #38bdf8;
    --azure-dark: #0284c7;

    --green: #22c55e;
    --green-dark: #15803d;

    --red: #ef4444;
    --red-dark: #991b1b;

    --yellow: #f59e0b;

    --shadow:
        0 20px 50px rgba(0,0,0,.25);
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;

    background:
        radial-gradient(
            circle at 15% 10%,
            rgba(14,165,233,.10),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 20%,
            rgba(34,197,94,.07),
            transparent 25%
        ),
        var(--bg);

    color: var(--text);

    font-family:
        Inter,
        Segoe UI,
        Roboto,
        Arial,
        sans-serif;
}}

.header {{
    position: sticky;
    top: 0;
    z-index: 50;

    backdrop-filter: blur(18px);

    background: rgba(7,17,31,.82);

    border-bottom: 1px solid var(--border);
}}

.header-inner {{
    max-width: 1500px;
    margin: auto;

    padding: 18px 30px;

    display: flex;
    justify-content: space-between;
    align-items: center;

    gap: 20px;
}}

.brand {{
    display: flex;
    align-items: center;
    gap: 14px;
}}

.brand-icon {{
    width: 44px;
    height: 44px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            #0ea5e9,
            #2563eb
        );

    box-shadow:
        0 10px 30px rgba(14,165,233,.25);

    font-size: 21px;
}}

.brand h1 {{
    margin: 0;

    font-size: 18px;
    font-weight: 700;
}}

.brand p {{
    margin: 3px 0 0;

    color: var(--muted);
    font-size: 12px;
}}

.header-status {{
    display: flex;
    align-items: center;
    gap: 10px;

    padding: 8px 13px;

    background: rgba(34,197,94,.08);

    border: 1px solid rgba(34,197,94,.22);

    border-radius: 999px;

    color: #86efac;

    font-size: 12px;
    font-weight: 600;
}}

.status-dot {{
    width: 8px;
    height: 8px;

    border-radius: 50%;

    background: var(--green);

    box-shadow:
        0 0 0 5px rgba(34,197,94,.10),
        0 0 15px rgba(34,197,94,.7);
}}

.container {{
    max-width: 1500px;
    margin: auto;

    padding: 30px;
}}

.hero {{
    position: relative;

    overflow: hidden;

    padding: 34px;

    border-radius: 20px;

    background:
        linear-gradient(
            135deg,
            rgba(20,83,45,.75),
            rgba(15,28,46,.95)
        );

    border: 1px solid rgba(34,197,94,.28);

    box-shadow: var(--shadow);

    margin-bottom: 24px;
}}

.hero::after {{
    content: "";

    position: absolute;

    width: 300px;
    height: 300px;

    right: -100px;
    top: -150px;

    border-radius: 50%;

    background:
        radial-gradient(
            circle,
            rgba(34,197,94,.18),
            transparent 70%
        );
}}

.hero-content {{
    position: relative;
    z-index: 2;
}}

.hero-top {{
    display: flex;
    align-items: center;
    gap: 15px;
}}

.hero-icon {{
    width: 52px;
    height: 52px;

    border-radius: 15px;

    background: rgba(34,197,94,.15);

    border: 1px solid rgba(34,197,94,.3);

    display: flex;
    align-items: center;
    justify-content: center;

    font-size: 25px;
}}

.hero h2 {{
    margin: 0;

    font-size: 27px;
}}

.hero p {{
    margin: 7px 0 0;

    color: #bbf7d0;
}}

.hero-meta {{
    display: flex;
    flex-wrap: wrap;

    gap: 10px;

    margin-top: 25px;
}}

.meta {{
    padding: 8px 12px;

    border-radius: 8px;

    background: rgba(0,0,0,.18);

    border: 1px solid rgba(255,255,255,.08);

    color: #d1fae5;

    font-size: 12px;
}}

.grid {{
    display: grid;

    grid-template-columns:
        repeat(4, minmax(0, 1fr));

    gap: 16px;

    margin-bottom: 24px;
}}

.card {{
    background:
        linear-gradient(
            145deg,
            rgba(19,36,58,.95),
            rgba(11,22,40,.95)
        );

    border: 1px solid var(--border);

    border-radius: 16px;

    padding: 20px;

    box-shadow:
        0 12px 30px rgba(0,0,0,.16);

    transition:
        transform .2s ease,
        border-color .2s ease;
}}

.card:hover {{
    transform: translateY(-2px);

    border-color:
        rgba(56,189,248,.35);
}}

.card-header {{
    display: flex;

    justify-content: space-between;
    align-items: center;
}}

.card-label {{
    color: var(--muted);

    font-size: 11px;

    text-transform: uppercase;

    letter-spacing: .08em;

    font-weight: 700;
}}

.card-icon {{
    width: 32px;
    height: 32px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 9px;

    background: rgba(56,189,248,.08);

    color: var(--azure);
}}

.card-value {{
    margin-top: 13px;

    font-size: 20px;

    font-weight: 700;

    word-break: break-word;
}}

.card-sub {{
    margin-top: 7px;

    color: var(--muted);

    font-size: 11px;
}}

.green {{
    color: #4ade80;
}}

.blue {{
    color: #38bdf8;
}}

.yellow {{
    color: #fbbf24;
}}

.layout {{
    display: grid;

    grid-template-columns:
        minmax(0, 2fr)
        minmax(320px, 1fr);

    gap: 20px;
}}

.panel {{
    background:
        linear-gradient(
            145deg,
            rgba(15,28,46,.98),
            rgba(9,20,35,.98)
        );

    border: 1px solid var(--border);

    border-radius: 18px;

    overflow: hidden;

    box-shadow: var(--shadow);

    margin-bottom: 20px;
}}

.panel-header {{
    padding: 20px 22px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    gap: 15px;

    border-bottom: 1px solid var(--border);
}}

.panel-title {{
    display: flex;

    align-items: center;

    gap: 11px;
}}

.panel-title-icon {{
    width: 34px;
    height: 34px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 9px;

    background: rgba(56,189,248,.09);

    color: var(--azure);
}}

.panel h3 {{
    margin: 0;

    font-size: 15px;
}}

.panel-description {{
    margin-top: 4px;

    color: var(--muted);

    font-size: 11px;
}}

.panel-body {{
    padding: 22px;
}}

.search {{
    width: 240px;

    padding: 9px 12px;

    border-radius: 9px;

    border: 1px solid var(--border);

    background: #091526;

    color: white;

    outline: none;
}}

.search:focus {{
    border-color: var(--azure);
}}

table {{
    width: 100%;

    border-collapse: collapse;
}}

th {{
    padding: 13px 14px;

    text-align: left;

    color: #7890aa;

    background: #0b192c;

    font-size: 10px;

    text-transform: uppercase;

    letter-spacing: .06em;
}}

td {{
    padding: 14px;

    border-top: 1px solid rgba(32,51,77,.65);

    vertical-align: middle;

    font-size: 12px;
}}

tr {{
    transition: background .15s ease;
}}

tbody tr:hover {{
    background: rgba(56,189,248,.035);
}}

.time {{
    color: #a7bad0;

    font-family: monospace;

    font-size: 11px;
}}

.host {{
    display: flex;
    align-items: center;

    gap: 9px;
}}

.host-icon {{
    width: 31px;
    height: 31px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 8px;

    background: rgba(56,189,248,.10);

    color: var(--azure);

    font-size: 9px;
    font-weight: 800;
}}

.host strong {{
    display: block;
}}

.host small {{
    display: block;

    margin-top: 2px;

    color: var(--muted);

    font-family: monospace;
}}

.process {{
    padding: 5px 8px;

    background: rgba(56,189,248,.07);

    border: 1px solid rgba(56,189,248,.12);

    border-radius: 6px;

    color: #7dd3fc;

    font-family: monospace;

    font-size: 11px;
}}

.severity {{
    display: inline-flex;

    padding: 5px 8px;

    border-radius: 999px;

    font-size: 9px;

    font-weight: 800;

    letter-spacing: .05em;
}}

.severity-info {{
    color: #7dd3fc;

    background: rgba(14,165,233,.10);
}}

.severity-warning {{
    color: #fcd34d;

    background: rgba(245,158,11,.10);
}}

.severity-error,
.severity-critical {{
    color: #fca5a5;

    background: rgba(239,68,68,.10);
}}

.message-cell {{
    max-width: 430px;

    color: #aabbd0;

    line-height: 1.5;
}}

.details-btn {{
    cursor: pointer;

    border: 1px solid #29405c;

    background: #12243a;

    color: #7dd3fc;

    border-radius: 7px;

    padding: 6px 10px;

    font-size: 10px;
}}

.details-btn:hover {{
    background: #18324f;

    border-color: #38bdf8;
}}

.query {{
    margin: 0;

    padding: 18px;

    border-radius: 11px;

    background: #06101d;

    border: 1px solid #182b42;

    color: #bae6fd;

    font-family:
        "SFMono-Regular",
        Consolas,
        monospace;

    font-size: 12px;

    line-height: 1.7;

    overflow-x: auto;
}}

.copy-btn {{
    cursor: pointer;

    padding: 7px 10px;

    border-radius: 7px;

    border: 1px solid #29405c;

    background: #102238;

    color: #93c5fd;

    font-size: 10px;
}}

.architecture {{
    display: flex;

    align-items: center;

    justify-content: center;

    gap: 10px;

    flex-wrap: wrap;
}}

.arch-node {{
    min-width: 135px;

    padding: 16px 13px;

    border-radius: 12px;

    text-align: center;

    background:
        linear-gradient(
            145deg,
            #132a43,
            #0d1c30
        );

    border: 1px solid #254361;
}}

.arch-node .icon {{
    font-size: 22px;
}}

.arch-node strong {{
    display: block;

    margin-top: 7px;

    font-size: 11px;
}}

.arch-node small {{
    display: block;

    margin-top: 4px;

    color: var(--muted);

    font-size: 9px;
}}

.arrow {{
    color: #38bdf8;

    font-size: 18px;
}}

.info-list {{
    display: grid;

    gap: 10px;
}}

.info-row {{
    display: flex;

    justify-content: space-between;

    gap: 20px;

    padding-bottom: 10px;

    border-bottom: 1px solid rgba(32,51,77,.6);

    font-size: 12px;
}}

.info-row:last-child {{
    border-bottom: none;
}}

.info-label {{
    color: var(--muted);
}}

.info-value {{
    text-align: right;

    color: #dbeafe;

    font-family: monospace;

    word-break: break-word;
}}

.modal {{
    position: fixed;

    inset: 0;

    z-index: 100;

    display: none;

    align-items: center;

    justify-content: center;

    padding: 25px;

    background: rgba(0,0,0,.72);

    backdrop-filter: blur(7px);
}}

.modal.active {{
    display: flex;
}}

.modal-box {{
    width: min(900px, 100%);

    max-height: 85vh;

    overflow: auto;

    background: #0c1a2c;

    border: 1px solid #29405c;

    border-radius: 18px;

    box-shadow:
        0 30px 100px rgba(0,0,0,.55);
}}

.modal-header {{
    position: sticky;

    top: 0;

    background: #0c1a2c;

    display: flex;

    justify-content: space-between;

    align-items: center;

    padding: 18px 20px;

    border-bottom: 1px solid var(--border);
}}

.modal-header h3 {{
    margin: 0;
}}

.close {{
    cursor: pointer;

    width: 32px;
    height: 32px;

    border: none;

    border-radius: 8px;

    background: #17283d;

    color: white;
}}

.modal-body {{
    padding: 20px;
}}

.json {{
    margin: 0;

    padding: 18px;

    background: #06101d;

    border-radius: 10px;

    overflow: auto;

    white-space: pre-wrap;

    color: #bae6fd;

    font-size: 11px;

    line-height: 1.6;
}}

.footer {{
    padding: 25px 0 10px;

    text-align: center;

    color: #61758e;

    font-size: 11px;
}}

@media(max-width: 1100px) {{

    .grid {{
        grid-template-columns:
            repeat(2, minmax(0, 1fr));
    }}

    .layout {{
        grid-template-columns: 1fr;
    }}

}}

@media(max-width: 700px) {{

    .container {{
        padding: 18px;
    }}

    .header-inner {{
        padding: 14px 18px;
    }}

    .header-status {{
        display: none;
    }}

    .grid {{
        grid-template-columns: 1fr;
    }}

    .hero {{
        padding: 24px;
    }}

    .hero h2 {{
        font-size: 21px;
    }}

    .panel {{
        overflow-x: auto;
    }}

    .panel-header {{
        align-items: flex-start;

        flex-direction: column;
    }}

    .search {{
        width: 100%;
    }}

}}

</style>

</head>

<body>

<header class="header">

    <div class="header-inner">

        <div class="brand">

            <div class="brand-icon">
                🛡
            </div>

            <div>
                <h1>Azure NSP Security Dashboard</h1>

                <p>
                    Network Security Perimeter validation
                </p>
            </div>

        </div>

        <div class="header-status">

            <span class="status-dot"></span>

            LIVE MONITORING

        </div>

    </div>

</header>


<main class="container">


<!-- HERO -->

<section class="hero">

    <div class="hero-content">

        <div class="hero-top">

            <div class="hero-icon">
                ✓
            </div>

            <div>

                <h2>
                    Network Security Perimeter Allows Access
                </h2>

                <p>
                    The workload successfully accessed the protected
                    Log Analytics workspace.
                </p>

            </div>

        </div>


        <div class="hero-meta">

            <div class="meta">
                ● Status: <strong>SUCCESS</strong>
            </div>

            <div class="meta">
                Identity: <strong>Managed Identity</strong>
            </div>

            <div class="meta">
                NSP: <strong>ENFORCED</strong>
            </div>

            <div class="meta">
                Workspace: <strong>{html_escape(WORKSPACE_NAME)}</strong>
            </div>

        </div>

    </div>

</section>


<!-- KPI CARDS -->

<section class="grid">

    <div class="card">

        <div class="card-header">

            <div class="card-label">
                Authentication
            </div>

            <div class="card-icon">
                🔐
            </div>

        </div>

        <div class="card-value blue">
            Managed Identity
        </div>

        <div class="card-sub">
            Azure workload identity
        </div>

    </div>


    <div class="card">

        <div class="card-header">

            <div class="card-label">
                Traffic Decision
            </div>

            <div class="card-icon">
                ✓
            </div>

        </div>

        <div class="card-value green">
            ALLOWED
        </div>

        <div class="card-sub">
            NSP validation passed
        </div>

    </div>


    <div class="card">

        <div class="card-header">

            <div class="card-label">
                Rows Returned
            </div>

            <div class="card-icon">
                #
            </div>

        </div>

        <div class="card-value">
            {row_count}
        </div>

        <div class="card-sub">
            Syslog records
        </div>

    </div>


    <div class="card">

        <div class="card-header">

            <div class="card-label">
                Tables
            </div>

            <div class="card-icon">
                ▦
            </div>

        </div>

        <div class="card-value">
            {table_count}
        </div>

        <div class="card-sub">
            Log Analytics tables
        </div>

    </div>


    <div class="card">

        <div class="card-header">

            <div class="card-label">
                NSP Mode
            </div>

            <div class="card-icon">
                🛡
            </div>

        </div>

        <div class="card-value green">
            ENFORCED
        </div>

        <div class="card-sub">
            Network boundary active
        </div>

    </div>


    <div class="card">

        <div class="card-header">

            <div class="card-label">
                Service Tag
            </div>

            <div class="card-icon">
                ☁
            </div>

        </div>

        <div class="card-value" style="font-size:14px;">
            {html_escape(NSP_SERVICE_TAG)}
        </div>

        <div class="card-sub">
            Azure Australia East
        </div>

    </div>


    <div class="card">

        <div class="card-header">

            <div class="card-label">
                Workspace
            </div>

            <div class="card-icon">
                ◈
            </div>

        </div>

        <div class="card-value" style="font-size:15px;">
            {html_escape(WORKSPACE_NAME)}
        </div>

        <div class="card-sub">
            Log Analytics Workspace
        </div>

    </div>


    <div class="card">

        <div class="card-header">

            <div class="card-label">
                Last Validation
            </div>

            <div class="card-icon">
                ◷
            </div>

        </div>

        <div class="card-value" style="font-size:14px;">
            {html_escape(timestamp)}
        </div>

        <div class="card-sub">
            UTC
        </div>

    </div>

</section>


<!-- MAIN CONTENT -->

<div class="layout">


<div>


<!-- LOG RECORDS -->

<section class="panel">

    <div class="panel-header">

        <div class="panel-title">

            <div class="panel-title-icon">
                ◉
            </div>

            <div>

                <h3>Live Syslog Records</h3>

                <div class="panel-description">
                    Latest records retrieved from Log Analytics
                </div>

            </div>

        </div>

        <input
            class="search"
            id="logSearch"
            type="search"
            placeholder="Search logs..."
            onkeyup="filterLogs()"
        >

    </div>


    <div style="overflow-x:auto;">

        <table>

            <thead>

                <tr>

                    <th>Time</th>
                    <th>Host</th>
                    <th>Process</th>
                    <th>Severity</th>
                    <th>Message</th>
                    <th></th>

                </tr>

            </thead>

            <tbody id="logTable">

                {rows_html}

            </tbody>

        </table>

    </div>

</section>


<!-- QUERY -->

<section class="panel">

    <div class="panel-header">

        <div class="panel-title">

            <div class="panel-title-icon">
                &gt;_
            </div>

            <div>

                <h3>Log Analytics Query</h3>

                <div class="panel-description">
                    Kusto Query Language executed against the workspace
                </div>

            </div>

        </div>

        <button
            class="copy-btn"
            onclick="copyQuery()">

            Copy Query

        </button>

    </div>


    <div class="panel-body">

        <pre
            class="query"
            id="query">{html_escape(QUERY)}</pre>

    </div>

</section>


<!-- ARCHITECTURE -->

<section class="panel">

    <div class="panel-header">

        <div class="panel-title">

            <div class="panel-title-icon">
                ◇
            </div>

            <div>

                <h3>Security Architecture</h3>

                <div class="panel-description">
                    Request path used during validation
                </div>

            </div>

        </div>

    </div>


    <div class="panel-body">

        <div class="architecture">

            <div class="arch-node">

                <div class="icon">🚀</div>

                <strong>Azure Container App</strong>

                <small>Workload</small>

            </div>


            <div class="arrow">→</div>


            <div class="arch-node">

                <div class="icon">🔐</div>

                <strong>Managed Identity</strong>

                <small>Authentication</small>

            </div>


            <div class="arrow">→</div>


            <div class="arch-node">

                <div class="icon">🛡</div>

                <strong>Network Security Perimeter</strong>

                <small>Policy Enforcement</small>

            </div>


            <div class="arrow">→</div>


            <div class="arch-node">

                <div class="icon">📊</div>

                <strong>Log Analytics</strong>

                <small>Protected Workspace</small>

            </div>

        </div>

    </div>

</section>


</div>


<!-- RIGHT SIDEBAR -->

<div>


<section class="panel">

    <div class="panel-header">

        <div class="panel-title">

            <div class="panel-title-icon">
                ✓
            </div>

            <div>

                <h3>Validation Summary</h3>

                <div class="panel-description">
                    Current security posture
                </div>

            </div>

        </div>

    </div>


    <div class="panel-body">

        <div class="info-list">

            <div class="info-row">

                <span class="info-label">
                    Status
                </span>

                <span class="info-value green">
                    SUCCESS
                </span>

            </div>


            <div class="info-row">

                <span class="info-label">
                    Identity
                </span>

                <span class="info-value">
                    Managed Identity
                </span>

            </div>


            <div class="info-row">

                <span class="info-label">
                    NSP Decision
                </span>

                <span class="info-value green">
                    ALLOWED
                </span>

            </div>


            <div class="info-row">

                <span class="info-label">
                    NSP Mode
                </span>

                <span class="info-value">
                    ENFORCED
                </span>

            </div>


            <div class="info-row">

                <span class="info-label">
                    Tables
                </span>

                <span class="info-value">
                    {table_count}
                </span>

            </div>


            <div class="info-row">

                <span class="info-label">
                    Records
                </span>

                <span class="info-value">
                    {row_count}
                </span>

            </div>

        </div>

    </div>

</section>


<section class="panel">

    <div class="panel-header">

        <div class="panel-title">

            <div class="panel-title-icon">
                ☁
            </div>

            <div>

                <h3>Workspace Details</h3>

                <div class="panel-description">
                    Protected Azure resource
                </div>

            </div>

        </div>

    </div>


    <div class="panel-body">

        <div class="info-list">

            <div class="info-row">

                <span class="info-label">
                    Name
                </span>

                <span class="info-value">
                    {html_escape(WORKSPACE_NAME)}
                </span>

            </div>


            <div class="info-row">

                <span class="info-label">
                    Workspace ID
                </span>

                <span class="info-value">
                    {html_escape(WORKSPACE_ID)}
                </span>

            </div>


            <div class="info-row">

                <span class="info-label">
                    Service Tag
                </span>

                <span class="info-value">
                    {html_escape(NSP_SERVICE_TAG)}
                </span>

            </div>


            <div class="info-row">

                <span class="info-label">
                    Query Window
                </span>

                <span class="info-value">
                    Last 24 hours
                </span>

            </div>

        </div>

    </div>

</section>


<section class="panel">

    <div class="panel-header">

        <div class="panel-title">

            <div class="panel-title-icon">
                ✓
            </div>

            <div>

                <h3>Security Result</h3>

                <div class="panel-description">
                    NSP enforcement result
                </div>

            </div>

        </div>

    </div>


    <div class="panel-body">

        <div style="
            padding:20px;
            border-radius:12px;
            background:rgba(34,197,94,.07);
            border:1px solid rgba(34,197,94,.2);
        ">

            <div style="
                color:#4ade80;
                font-size:14px;
                font-weight:800;
            ">

                ✓ ACCESS ALLOWED

            </div>

            <div style="
                margin-top:8px;
                color:#94a3b8;
                font-size:11px;
                line-height:1.6;
            ">

                The authenticated workload successfully
                passed Network Security Perimeter validation
                and queried the protected workspace.

            </div>

        </div>

    </div>

</section>


</div>

</div>


<footer class="footer">

    Azure Container App
    →
    Managed Identity
    →
    Network Security Perimeter
    →
    Protected Log Analytics Workspace

</footer>

</main>


<!-- RECORD MODAL -->

<div class="modal" id="recordModal">

    <div class="modal-box">

        <div class="modal-header">

            <h3>Syslog Record</h3>

            <button
                class="close"
                onclick="closeRecord()">

                ×

            </button>

        </div>

        <div class="modal-body">

            <pre
                class="json"
                id="recordContent"></pre>

        </div>

    </div>

</div>


<script>

function filterLogs() {{

    const input =
        document
            .getElementById("logSearch")
            .value
            .toLowerCase();

    const rows =
        document
            .querySelectorAll("#logTable tr");

    rows.forEach(row => {{

        const text =
            row
                .getAttribute("data-search")
                .toLowerCase();

        row.style.display =
            text.includes(input)
                ? ""
                : "none";

    }});

}}


function showRecord(record) {{

    document
        .getElementById("recordContent")
        .textContent =
        JSON.stringify(record, null, 2);

    document
        .getElementById("recordModal")
        .classList.add("active");

}}


function closeRecord() {{

    document
        .getElementById("recordModal")
        .classList.remove("active");

}}


document
    .getElementById("recordModal")
    .addEventListener("click", function(event) {{

        if (event.target === this) {{
            closeRecord();
        }}

    }});


function copyQuery() {{

    const query =
        document
            .getElementById("query")
            .innerText;

    navigator.clipboard
        .writeText(query)
        .then(() => {{

            const button =
                document.querySelector(".copy-btn");

            const original =
                button.innerText;

            button.innerText =
                "Copied ✓";

            setTimeout(() => {{
                button.innerText = original;
            }}, 1500);

        }});

}}

</script>

</body>

</html>
"""


def build_blocked_page(error_text, exception_type, source_ip):

    nsp_error = extract_nsp_error(error_text)

    safe_error = html_escape(error_text)
    safe_trace = html_escape(traceback.format_exc())

    return f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>Azure NSP - Access Blocked</title>

<style>

:root {{
    --bg: #070d17;
    --panel: #101927;
    --panel2: #0c1523;
    --border: #29394d;

    --text: #f8fafc;
    --muted: #94a3b8;

    --red: #ef4444;
    --red-light: #fca5a5;

    --yellow: #f59e0b;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;

    background:
        radial-gradient(
            circle at 50% -10%,
            rgba(239,68,68,.12),
            transparent 35%
        ),
        var(--bg);

    color: var(--text);

    font-family:
        Inter,
        Segoe UI,
        Arial,
        sans-serif;
}}

.header {{
    border-bottom: 1px solid var(--border);

    background: rgba(7,13,23,.88);

    backdrop-filter: blur(16px);
}}

.header-inner {{
    max-width: 1200px;

    margin: auto;

    padding: 20px 25px;

    display: flex;
    align-items: center;

    gap: 14px;
}}

.logo {{
    width: 44px;
    height: 44px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            #991b1b,
            #ef4444
        );

    font-size: 21px;
}}

.header h1 {{
    margin: 0;

    font-size: 18px;
}}

.header p {{
    margin: 4px 0 0;

    color: var(--muted);

    font-size: 11px;
}}

.container {{
    max-width: 1200px;

    margin: auto;

    padding: 30px 25px 50px;
}}

.hero {{
    padding: 35px;

    border-radius: 20px;

    background:
        linear-gradient(
            135deg,
            rgba(127,29,29,.75),
            rgba(16,25,39,.95)
        );

    border:
        1px solid rgba(239,68,68,.35);

    box-shadow:
        0 25px 70px rgba(0,0,0,.3);

    margin-bottom: 20px;
}}

.hero-content {{
    display: flex;

    align-items: center;

    gap: 18px;
}}

.hero-icon {{
    width: 60px;
    height: 60px;

    flex-shrink: 0;

    border-radius: 17px;

    display: flex;
    align-items: center;
    justify-content: center;

    background: rgba(239,68,68,.14);

    border: 1px solid rgba(239,68,68,.3);

    font-size: 27px;
}}

.hero h2 {{
    margin: 0;

    font-size: 27px;
}}

.hero p {{
    margin: 7px 0 0;

    color: #fecaca;

    line-height: 1.6;
}}

.grid {{
    display: grid;

    grid-template-columns:
        repeat(3, minmax(0, 1fr));

    gap: 16px;

    margin-bottom: 20px;
}}

.card {{
    padding: 20px;

    border-radius: 15px;

    background:
        linear-gradient(
            145deg,
            var(--panel),
            var(--panel2)
        );

    border: 1px solid var(--border);
}}

.label {{
    color: var(--muted);

    font-size: 10px;

    text-transform: uppercase;

    letter-spacing: .08em;

    font-weight: 700;
}}

.value {{
    margin-top: 9px;

    font-size: 16px;

    font-weight: 700;

    word-break: break-word;
}}

.red {{
    color: #f87171;
}}

.yellow {{
    color: #fbbf24;
}}

.panel {{
    margin-bottom: 20px;

    border-radius: 17px;

    overflow: hidden;

    background: var(--panel);

    border: 1px solid var(--border);

    box-shadow:
        0 15px 40px rgba(0,0,0,.18);
}}

.panel-header {{
    padding: 18px 20px;

    border-bottom: 1px solid var(--border);

    display: flex;
    align-items: center;

    gap: 12px;
}}

.panel-icon {{
    width: 34px;
    height: 34px;

    display: flex;
    align-items: center;
    justify-content: center;

    border-radius: 9px;

    background: rgba(239,68,68,.10);

    color: #f87171;
}}

.panel h3 {{
    margin: 0;

    font-size: 14px;
}}

.panel-body {{
    padding: 20px;
}}

.error-box {{
    padding: 17px;

    border-radius: 11px;

    background: rgba(239,68,68,.06);

    border: 1px solid rgba(239,68,68,.17);

    color: #fecaca;

    font-family: monospace;

    font-size: 11px;

    line-height: 1.7;

    overflow-wrap: anywhere;
}}

.nsp-code {{
    display: inline-block;

    margin-bottom: 10px;

    padding: 6px 9px;

    border-radius: 7px;

    background: rgba(239,68,68,.12);

    color: #fca5a5;

    font-size: 10px;

    font-weight: 800;
}}

.nsp-message {{
    color: #f8fafc;

    line-height: 1.7;
}}

details {{
    border-top: 1px solid var(--border);
}}

summary {{
    cursor: pointer;

    padding: 17px 20px;

    color: #cbd5e1;

    font-size: 12px;

    font-weight: 600;
}}

pre {{
    margin: 0;

    padding: 20px;

    max-height: 400px;

    overflow: auto;

    background: #070f1b;

    color: #cbd5e1;

    font-family:
        "SFMono-Regular",
        Consolas,
        monospace;

    font-size: 10px;

    line-height: 1.6;

    white-space: pre-wrap;

    overflow-wrap: anywhere;
}}

.architecture {{
    display: flex;

    align-items: center;

    justify-content: center;

    gap: 10px;

    flex-wrap: wrap;
}}

.node {{
    min-width: 150px;

    padding: 16px;

    text-align: center;

    border-radius: 12px;

    background: #111f32;

    border: 1px solid #2a4059;
}}

.node strong {{
    display: block;

    margin-top: 7px;

    font-size: 11px;
}}

.node small {{
    display: block;

    margin-top: 4px;

    color: var(--muted);

    font-size: 9px;
}}

.arrow {{
    color: #64748b;

    font-size: 18px;
}}

.footer {{
    text-align: center;

    color: #64748b;

    font-size: 10px;

    margin-top: 30px;
}}

@media(max-width: 800px) {{

    .grid {{
        grid-template-columns: 1fr;
    }}

    .hero {{
        padding: 25px;
    }}

    .hero-content {{
        align-items: flex-start;
    }}

    .hero h2 {{
        font-size: 21px;
    }}

}}

</style>

</head>

<body>

<header class="header">

    <div class="header-inner">

        <div class="logo">
            🛡
        </div>

        <div>

            <h1>
                Azure NSP Security Dashboard
            </h1>

            <p>
                Network Security Perimeter validation
            </p>

        </div>

    </div>

</header>


<main class="container">


<section class="hero">

    <div class="hero-content">

        <div class="hero-icon">
            !
        </div>

        <div>

            <h2>
                Network Security Perimeter Blocked Access
            </h2>

            <p>
                The workload was authenticated, but the request
                failed Network Security Perimeter validation.
            </p>

        </div>

    </div>

</section>


<section class="grid">

    <div class="card">

        <div class="label">
            Authentication
        </div>

        <div class="value">
            Managed Identity
        </div>

    </div>


    <div class="card">

        <div class="label">
            Traffic Decision
        </div>

        <div class="value red">
            DENIED
        </div>

    </div>


    <div class="card">

        <div class="label">
            Failure Type
        </div>

        <div class="value red">
            NspValidationFailedError
        </div>

    </div>


    <div class="card">

        <div class="label">
            Source IP
        </div>

        <div class="value yellow">
            {html_escape(source_ip)}
        </div>

    </div>


    <div class="card">

        <div class="label">
            Workspace
        </div>

        <div class="value">
            {html_escape(WORKSPACE_NAME)}
        </div>

    </div>


    <div class="card">

        <div class="label">
            Status
        </div>

        <div class="value red">
            FAILED
        </div>

    </div>

</section>


<section class="panel">

    <div class="panel-header">

        <div class="panel-icon">
            !
        </div>

        <div>

            <h3>
                NSP Validation Result
            </h3>

        </div>

    </div>


    <div class="panel-body">

        <div class="error-box">

            <div class="nsp-code">
                {html_escape(nsp_error["code"])}
            </div>

            <div class="nsp-message">
                {html_escape(nsp_error["message"])}
            </div>

        </div>

    </div>

</section>


<section class="panel">

    <div class="panel-header">

        <div class="panel-icon">
            #
        </div>

        <div>

            <h3>
                Technical Error
            </h3>

        </div>

    </div>


    <div class="panel-body">

        <div class="error-box">

            {safe_error}

        </div>

    </div>

</section>


<section class="panel">

    <div class="panel-header">

        <div class="panel-icon">
            ◇
        </div>

        <div>

            <h3>
                Request Architecture
            </h3>

        </div>

    </div>


    <div class="panel-body">

        <div class="architecture">

            <div class="node">

                <div>🚀</div>

                <strong>
                    Azure Container App
                </strong>

                <small>
                    Workload
                </small>

            </div>

            <div class="arrow">
                →
            </div>

            <div class="node">

                <div>🔐</div>

                <strong>
                    Managed Identity
                </strong>

                <small>
                    Authentication
                </small>

            </div>

            <div class="arrow">
                →
            </div>

            <div class="node"
                 style="
                 border-color:rgba(239,68,68,.4);
                 background:rgba(127,29,29,.16);
                 ">

                <div>🛡</div>

                <strong>
                    Network Security Perimeter
                </strong>

                <small>
                    BLOCKED
                </small>

            </div>

            <div class="arrow">
                →
            </div>

            <div class="node">

                <div>📊</div>

                <strong>
                    Log Analytics
                </strong>

                <small>
                    Protected Workspace
                </small>

            </div>

        </div>

    </div>

</section>


<details class="panel">

    <summary>
        View Python Stack Trace
    </summary>

    <pre>{safe_trace}</pre>

</details>


<footer class="footer">

    Azure Container App
    →
    Managed Identity
    →
    Network Security Perimeter
    →
    Log Analytics Workspace

</footer>


</main>

</body>

</html>
"""


@app.route("/")
def index():

    try:

        records, table_count = get_logs()

        return build_allowed_page(
            records,
            table_count
        )

    except Exception as ex:

        error_text = str(ex)

        source_ip = extract_source_ip(error_text)

        exception_type = type(ex).__name__

        return (
            build_blocked_page(
                error_text,
                exception_type,
                source_ip
            ),
            500
        )


@app.route("/api/status")
def api_status():

    timestamp = utc_now().isoformat()

    try:

        records, table_count = get_logs()

        return jsonify({
            "status": "success",
            "identity": "Managed Identity",
            "workspace": WORKSPACE_ID,
            "query": QUERY,
            "rowCount": len(records),
            "tableCount": table_count,
            "sampleRecords": records,
            "timestamp": timestamp
        })

    except Exception as ex:

        error_text = str(ex)

        source_ip = extract_source_ip(error_text)

        nsp_error = extract_nsp_error(error_text)

        return jsonify({
            "status": "failed",
            "identity": "Managed Identity",
            "workspace": WORKSPACE_ID,
            "exceptionType": type(ex).__name__,
            "error": error_text,
            "nspError": nsp_error,
            "sourceIP": source_ip,
            "trace": traceback.format_exc(),
            "timestamp": timestamp
        }), 500


@app.route("/health")
def health():

    return {
        "status": "healthy",
        "workspace": WORKSPACE_ID
    }


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False
    )
