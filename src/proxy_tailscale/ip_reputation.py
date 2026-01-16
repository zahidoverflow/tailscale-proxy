"""
IP Reputation Checker - Multi-source IP intelligence with Rich terminal UI.

Usage:
    from proxy_tailscale.ip_reputation import check_ip_reputation
    check_ip_reputation("71.72.50.76")

Optional API keys can be configured in ~/.config/tailscale-proxy/api_keys.json:
{
    "ipqualityscore": "your_key_here",
    "abuseipdb": "your_key_here",
    "virustotal": "your_key_here"
}
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

console = Console()

# Config paths
CONFIG_DIR = Path.home() / ".config" / "tailscale-proxy"
API_KEYS_FILE = CONFIG_DIR / "api_keys.json"


@dataclass
class ReputationResult:
    """Result from a single reputation source."""
    source: str
    success: bool
    fraud_score: int | None = None
    risk_level: str = "unknown"
    is_vpn: bool | None = None
    is_proxy: bool | None = None
    is_tor: bool | None = None
    is_datacenter: bool | None = None
    is_residential: bool | None = None
    isp: str = ""
    org: str = ""
    hostname: str = ""
    country: str = ""
    city: str = ""
    region: str = ""
    asn: str = ""
    abuse_score: int | None = None
    blacklists: dict[str, bool] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class AggregatedReputation:
    """Aggregated reputation from all sources."""
    ip: str
    results: list[ReputationResult] = field(default_factory=list)
    
    @property
    def avg_fraud_score(self) -> float | None:
        scores = [r.fraud_score for r in self.results if r.fraud_score is not None]
        return sum(scores) / len(scores) if scores else None
    
    @property
    def is_clean(self) -> bool:
        avg = self.avg_fraud_score
        if avg is None:
            return True
        return avg < 30
    
    @property
    def overall_risk(self) -> str:
        avg = self.avg_fraud_score
        if avg is None:
            return "unknown"
        if avg < 20:
            return "low"
        if avg < 50:
            return "medium"
        if avg < 75:
            return "high"
        return "critical"


def load_api_keys() -> dict[str, str]:
    """Load API keys from config file."""
    if not API_KEYS_FILE.exists():
        return {}
    try:
        return json.loads(API_KEYS_FILE.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def save_api_keys(keys: dict[str, str]) -> None:
    """Save API keys to config file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    API_KEYS_FILE.write_text(json.dumps(keys, indent=2))


def _http_get(url: str, headers: dict[str, str] | None = None, timeout: int = 10) -> tuple[int, str]:
    """Simple HTTP GET request."""
    req = urllib.request.Request(url, headers=headers or {})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace") if e.fp else ""
    except Exception as e:
        return 0, str(e)


def _extract_between(text: str, start: str, end: str) -> str:
    """Extract text between two markers."""
    try:
        s = text.index(start) + len(start)
        e = text.index(end, s)
        return text[s:e].strip()
    except ValueError:
        return ""


# =============================================================================
# REPUTATION SOURCES
# =============================================================================

def check_scamalytics(ip: str) -> ReputationResult:
    """Check Scamalytics (no API key needed for basic info)."""
    result = ReputationResult(source="Scamalytics", success=False)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "identity",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    
    status, body = _http_get(f"https://scamalytics.com/ip/{ip}", headers=headers)
    
    if status != 200:
        result.error = f"HTTP {status}"
        return result
    
    # Extract fraud score
    score_match = re.search(r'"score"\s*:\s*"?(\d+)"?', body)
    if score_match:
        result.fraud_score = int(score_match.group(1))
    
    # Extract risk level
    risk_match = re.search(r'"risk"\s*:\s*"(\w+)"', body)
    if risk_match:
        result.risk_level = risk_match.group(1)
    
    # Extract ISP/Org
    if "ISP Name" in body:
        isp = _extract_between(body, "ISP Name</td>", "</td>")
        isp = re.sub(r"<[^>]+>", "", isp).strip()
        if isp:
            result.isp = isp
    
    if "Organization Name" in body:
        org = _extract_between(body, "Organization Name</td>", "</td>")
        org = re.sub(r"<[^>]+>", "", org).strip()
        if org:
            result.org = org
    
    # Hostname
    if "Hostname" in body:
        hostname = _extract_between(body, "Hostname</td>", "</td>")
        hostname = re.sub(r"<[^>]+>", "", hostname).strip()
        if hostname:
            result.hostname = hostname
    
    # Location
    if "City" in body:
        city = _extract_between(body, 'City</td>', "</td>")
        city = re.sub(r"<[^>]+>", "", city).strip()
        if city:
            result.city = city
    
    if "Country Name" in body:
        country = _extract_between(body, "Country Name</td>", "</td>")
        country = re.sub(r"<[^>]+>", "", country).strip()
        if country:
            result.country = country
    
    # Proxy/VPN detection
    result.is_vpn = "Anonymizing VPN</td>" in body and ">Yes<" in body.split("Anonymizing VPN")[1][:100]
    result.is_tor = "Tor Exit Node</td>" in body and ">Yes<" in body.split("Tor Exit Node")[1][:100]
    result.is_proxy = "Public Proxy</td>" in body and ">Yes<" in body.split("Public Proxy")[1][:100]
    result.is_datacenter = "Datacenter</td>" in body and ">Yes<" in body.split("Datacenter</td>")[1][:100]
    
    # Blacklists
    for bl in ["Firehol", "IP2ProxyLite", "IPsum", "Spamhaus"]:
        if bl in body:
            segment = body.split(bl)[1][:100] if bl in body else ""
            result.blacklists[bl] = ">Yes<" in segment
    
    result.success = True
    return result


def check_ipapi(ip: str) -> ReputationResult:
    """Check ip-api.com (free, no API key needed)."""
    result = ReputationResult(source="IP-API", success=False)
    
    status, body = _http_get(f"http://ip-api.com/json/{ip}?fields=66846719")
    
    if status != 200:
        result.error = f"HTTP {status}"
        return result
    
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        result.error = "Invalid JSON"
        return result
    
    if data.get("status") != "success":
        result.error = data.get("message", "Query failed")
        return result
    
    result.isp = data.get("isp", "")
    result.org = data.get("org", "")
    result.asn = data.get("as", "").split()[0] if data.get("as") else ""
    result.country = data.get("country", "")
    result.city = data.get("city", "")
    result.region = data.get("regionName", "")
    result.is_proxy = data.get("proxy", False)
    result.is_datacenter = data.get("hosting", False)
    result.extra["mobile"] = data.get("mobile", False)
    result.extra["lat"] = data.get("lat")
    result.extra["lon"] = data.get("lon")
    result.extra["timezone"] = data.get("timezone", "")
    
    result.success = True
    return result


def check_ipqualityscore(ip: str, api_key: str | None = None) -> ReputationResult:
    """Check IPQualityScore (API key optional but recommended)."""
    result = ReputationResult(source="IPQualityScore", success=False)
    
    if not api_key:
        result.error = "No API key (sign up at ipqualityscore.com for free tier)"
        return result
    
    url = f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip}?strictness=1&allow_public_access_points=true"
    status, body = _http_get(url)
    
    if status != 200:
        result.error = f"HTTP {status}"
        return result
    
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        result.error = "Invalid JSON"
        return result
    
    if not data.get("success", True):
        result.error = data.get("message", "Query failed")
        return result
    
    result.fraud_score = data.get("fraud_score")
    result.is_vpn = data.get("vpn", False)
    result.is_proxy = data.get("proxy", False)
    result.is_tor = data.get("tor", False)
    result.is_datacenter = data.get("is_crawler", False) or not data.get("ISP", "").strip()
    result.isp = data.get("ISP", "")
    result.org = data.get("organization", "")
    result.asn = str(data.get("ASN", ""))
    result.country = data.get("country_code", "")
    result.city = data.get("city", "")
    result.region = data.get("region", "")
    result.hostname = data.get("host", "")
    
    # Extra details
    result.extra["bot_status"] = data.get("bot_status", False)
    result.extra["recent_abuse"] = data.get("recent_abuse", False)
    result.extra["abuse_velocity"] = data.get("abuse_velocity", "")
    result.extra["connection_type"] = data.get("connection_type", "")
    
    if result.fraud_score is not None:
        if result.fraud_score < 30:
            result.risk_level = "low"
        elif result.fraud_score < 60:
            result.risk_level = "medium"
        elif result.fraud_score < 85:
            result.risk_level = "high"
        else:
            result.risk_level = "critical"
    
    result.success = True
    return result


def check_abuseipdb(ip: str, api_key: str | None = None) -> ReputationResult:
    """Check AbuseIPDB (API key required)."""
    result = ReputationResult(source="AbuseIPDB", success=False)
    
    if not api_key:
        result.error = "No API key (sign up at abuseipdb.com for free tier)"
        return result
    
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose=true"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    status, body = _http_get(url, headers=headers)
    
    if status != 200:
        result.error = f"HTTP {status}"
        return result
    
    try:
        data = json.loads(body).get("data", {})
    except json.JSONDecodeError:
        result.error = "Invalid JSON"
        return result
    
    result.abuse_score = data.get("abuseConfidenceScore")
    result.fraud_score = result.abuse_score  # Use abuse score as fraud score
    result.isp = data.get("isp", "")
    result.country = data.get("countryCode", "")
    result.is_tor = data.get("isTor", False)
    result.extra["total_reports"] = data.get("totalReports", 0)
    result.extra["num_distinct_users"] = data.get("numDistinctUsers", 0)
    result.extra["usage_type"] = data.get("usageType", "")
    result.extra["domain"] = data.get("domain", "")
    
    if result.abuse_score is not None:
        if result.abuse_score < 20:
            result.risk_level = "low"
        elif result.abuse_score < 50:
            result.risk_level = "medium"
        elif result.abuse_score < 80:
            result.risk_level = "high"
        else:
            result.risk_level = "critical"
    
    result.success = True
    return result


def check_virustotal(ip: str, api_key: str | None = None) -> ReputationResult:
    """Check VirusTotal (API key required)."""
    result = ReputationResult(source="VirusTotal", success=False)
    
    if not api_key:
        result.error = "No API key (sign up at virustotal.com for free tier)"
        return result
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    status, body = _http_get(url, headers=headers)
    
    if status != 200:
        result.error = f"HTTP {status}"
        return result
    
    try:
        data = json.loads(body).get("data", {}).get("attributes", {})
    except json.JSONDecodeError:
        result.error = "Invalid JSON"
        return result
    
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 1
    
    # Calculate fraud score based on detection ratio
    result.fraud_score = int(((malicious + suspicious) / max(total, 1)) * 100)
    result.asn = str(data.get("asn", ""))
    result.org = data.get("as_owner", "")
    result.country = data.get("country", "")
    
    result.extra["malicious_votes"] = malicious
    result.extra["suspicious_votes"] = suspicious
    result.extra["harmless_votes"] = stats.get("harmless", 0)
    result.extra["undetected_votes"] = stats.get("undetected", 0)
    result.extra["reputation"] = data.get("reputation", 0)
    
    if result.fraud_score < 5:
        result.risk_level = "low"
    elif result.fraud_score < 20:
        result.risk_level = "medium"
    elif result.fraud_score < 50:
        result.risk_level = "high"
    else:
        result.risk_level = "critical"
    
    result.success = True
    return result


def check_proxycheck(ip: str, api_key: str | None = None) -> ReputationResult:
    """Check proxycheck.io (free tier available without key)."""
    result = ReputationResult(source="ProxyCheck", success=False)
    
    url = f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1&port=1&seen=1&days=7"
    if api_key:
        url += f"&key={api_key}"
    
    status, body = _http_get(url)
    
    if status != 200:
        result.error = f"HTTP {status}"
        return result
    
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        result.error = "Invalid JSON"
        return result
    
    if data.get("status") != "ok":
        result.error = data.get("message", "Query failed")
        return result
    
    ip_data = data.get(ip, {})
    
    result.is_proxy = ip_data.get("proxy") == "yes"
    result.is_vpn = ip_data.get("type", "").lower() == "vpn"
    result.asn = ip_data.get("asn", "")
    result.org = ip_data.get("provider", "")
    result.isp = ip_data.get("isp", "") or ip_data.get("provider", "")
    result.country = ip_data.get("country", "")
    result.city = ip_data.get("city", "")
    result.region = ip_data.get("region", "")
    
    risk = ip_data.get("risk")
    if risk is not None:
        result.fraud_score = int(risk)
        if result.fraud_score < 34:
            result.risk_level = "low"
        elif result.fraud_score < 67:
            result.risk_level = "medium"
        else:
            result.risk_level = "high"
    
    result.extra["port"] = ip_data.get("port")
    result.extra["last_seen"] = ip_data.get("last seen human", "")
    
    result.success = True
    return result


def check_ipinfo(ip: str, api_key: str | None = None) -> ReputationResult:
    """Check ipinfo.io (free tier available, 50k/month)."""
    result = ReputationResult(source="IPinfo", success=False)
    
    url = f"https://ipinfo.io/{ip}/json"
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    
    status, body = _http_get(url, headers=headers if headers else None)
    
    if status != 200:
        result.error = f"HTTP {status}"
        return result
    
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        result.error = "Invalid JSON"
        return result
    
    result.hostname = data.get("hostname", "")
    result.isp = data.get("org", "")
    result.org = data.get("org", "")
    result.country = data.get("country", "")
    result.city = data.get("city", "")
    result.region = data.get("region", "")
    result.extra["postal"] = data.get("postal", "")
    result.extra["timezone"] = data.get("timezone", "")
    result.extra["loc"] = data.get("loc", "")
    
    # Check if it's a bogon (private/reserved IP)
    if data.get("bogon"):
        result.extra["bogon"] = True
    
    result.success = True
    return result


# =============================================================================
# MAIN CHECK FUNCTION
# =============================================================================

def check_ip_reputation(
    ip: str,
    api_keys: dict[str, str] | None = None,
    show_ui: bool = True,
) -> AggregatedReputation:
    """
    Check IP reputation across multiple sources.
    
    Args:
        ip: IP address to check
        api_keys: Optional dict of API keys (loads from config if not provided)
        show_ui: Whether to display Rich UI output
    
    Returns:
        AggregatedReputation with results from all sources
    """
    if api_keys is None:
        api_keys = load_api_keys()
    
    aggregated = AggregatedReputation(ip=ip)
    
    # Define all checks (free sources first, then API-required ones)
    checks = [
        ("IP-API", lambda: check_ipapi(ip)),
        ("IPinfo", lambda: check_ipinfo(ip, api_keys.get("ipinfo"))),
        ("ProxyCheck", lambda: check_proxycheck(ip, api_keys.get("proxycheck"))),
        ("Scamalytics", lambda: check_scamalytics(ip)),
        ("IPQualityScore", lambda: check_ipqualityscore(ip, api_keys.get("ipqualityscore"))),
        ("AbuseIPDB", lambda: check_abuseipdb(ip, api_keys.get("abuseipdb"))),
        ("VirusTotal", lambda: check_virustotal(ip, api_keys.get("virustotal"))),
    ]
    
    if show_ui:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(f"Checking {ip}...", total=len(checks))
            
            for name, check_fn in checks:
                progress.update(task, description=f"Checking {name}...")
                try:
                    result = check_fn()
                except Exception as e:
                    result = ReputationResult(source=name, success=False, error=str(e))
                aggregated.results.append(result)
                progress.advance(task)
    else:
        for name, check_fn in checks:
            try:
                result = check_fn()
            except Exception as e:
                result = ReputationResult(source=name, success=False, error=str(e))
            aggregated.results.append(result)
    
    if show_ui:
        display_reputation(aggregated)
    
    return aggregated


def display_reputation(rep: AggregatedReputation) -> None:
    """Display aggregated reputation in Rich UI."""
    
    # Overall verdict
    avg_score = rep.avg_fraud_score
    risk = rep.overall_risk
    
    risk_colors = {
        "low": "green",
        "medium": "yellow", 
        "high": "red",
        "critical": "bold red",
        "unknown": "dim",
    }
    
    risk_icons = {
        "low": "[OK]",
        "medium": "[!]",
        "high": "[!!]",
        "critical": "[XXX]",
        "unknown": "[?]",
    }
    
    color = risk_colors.get(risk, "white")
    icon = risk_icons.get(risk, "")
    
    score_text = f"{avg_score:.0f}/100" if avg_score is not None else "N/A"
    verdict = Text()
    verdict.append(f"\n{icon} ", style=f"bold {color}")
    verdict.append(f"Risk: {risk.upper()}", style=f"bold {color}")
    verdict.append(f"  |  Avg Fraud Score: ", style="dim")
    verdict.append(score_text, style=f"bold {color}")
    
    console.print(Panel(
        verdict,
        title=f"[bold]IP Reputation: {rep.ip}[/bold]",
        border_style=color,
    ))
    
    # Get best info from successful results
    info = _aggregate_info(rep.results)
    
    # =========================================================================
    # DETAILED IP INFORMATION PANEL
    # =========================================================================
    
    # Network info table (left column)
    net_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    net_table.add_column("Key", style="dim", width=14)
    net_table.add_column("Value", style="bold")
    
    net_table.add_row("IP Address", rep.ip)
    if info.get("hostname"):
        # Highlight residential hostnames
        hostname = info["hostname"]
        if ".res." in hostname or "residential" in hostname.lower():
            net_table.add_row("Hostname", f"[green]{hostname}[/green] [dim](residential)[/dim]")
        else:
            net_table.add_row("Hostname", hostname)
    if info.get("isp"):
        net_table.add_row("ISP", info["isp"])
    if info.get("org") and info.get("org") != info.get("isp"):
        net_table.add_row("Organization", info["org"])
    if info.get("asn"):
        net_table.add_row("ASN", info["asn"])
    
    # Connection type from extras
    conn_type = info.get("extra", {}).get("connection_type", "")
    if conn_type:
        net_table.add_row("Connection", conn_type)
    
    # Mobile network
    is_mobile = info.get("extra", {}).get("mobile")
    if is_mobile is True:
        net_table.add_row("Mobile", "[yellow]Yes (cellular)[/yellow]")
    elif is_mobile is False:
        net_table.add_row("Mobile", "[green]No (fixed line)[/green]")
    
    console.print(Panel(net_table, title="[bold]Network Details[/bold]", border_style="blue"))
    
    # Location info table
    loc_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
    loc_table.add_column("Key", style="dim", width=14)
    loc_table.add_column("Value", style="bold")
    
    if info.get("country"):
        loc_table.add_row("Country", info["country"])
    
    if info.get("region"):
        loc_table.add_row("Region/State", info["region"])
    if info.get("city"):
        loc_table.add_row("City", info["city"])
    
    # Postal code from extras
    postal = info.get("extra", {}).get("postal", "")
    if postal:
        loc_table.add_row("Postal Code", postal)
    
    # Coordinates
    lat = info.get("extra", {}).get("lat")
    lon = info.get("extra", {}).get("lon")
    loc_str = info.get("extra", {}).get("loc", "")
    if lat and lon:
        loc_table.add_row("Coordinates", f"{lat}, {lon}")
    elif loc_str:
        loc_table.add_row("Coordinates", loc_str)
    
    # Timezone
    timezone = info.get("extra", {}).get("timezone", "")
    if timezone:
        loc_table.add_row("Timezone", timezone)
    
    if loc_table.row_count > 0:
        console.print(Panel(loc_table, title="[bold]Location Details[/bold]", border_style="cyan"))
    
    # =========================================================================
    # DETECTION FLAGS (expanded)
    # =========================================================================
    
    flags_table = Table(show_header=False, box=None, padding=(0, 2))
    flags_table.add_column("Check", width=20)
    flags_table.add_column("Status", width=15)
    flags_table.add_column("Check", width=20)
    flags_table.add_column("Status", width=15)
    
    flag_checks = [
        ("VPN", info.get("is_vpn")),
        ("Proxy", info.get("is_proxy")),
        ("Tor Exit Node", info.get("is_tor")),
        ("Datacenter/Hosting", info.get("is_datacenter")),
        ("Bot/Crawler", info.get("extra", {}).get("bot_status")),
        ("Recent Abuse", info.get("extra", {}).get("recent_abuse")),
    ]
    
    def format_flag(value):
        if value is True:
            return "[red]! YES[/red]"
        elif value is False:
            return "[green]+ No[/green]"
        return "[dim]-[/dim]"
    
    # Add flags in pairs (2 columns)
    for i in range(0, len(flag_checks), 2):
        label1, val1 = flag_checks[i]
        if i + 1 < len(flag_checks):
            label2, val2 = flag_checks[i + 1]
            flags_table.add_row(label1, format_flag(val1), label2, format_flag(val2))
        else:
            flags_table.add_row(label1, format_flag(val1), "", "")
    
    console.print(Panel(flags_table, title="[bold]Security Flags[/bold]", border_style="yellow"))
    
    # =========================================================================
    # ABUSE METRICS (if available)
    # =========================================================================
    
    abuse_velocity = info.get("extra", {}).get("abuse_velocity", "")
    total_reports = info.get("extra", {}).get("total_reports")
    usage_type = info.get("extra", {}).get("usage_type", "")
    last_seen = info.get("extra", {}).get("last_seen", "")
    
    if any([abuse_velocity, total_reports, usage_type, last_seen]):
        abuse_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        abuse_table.add_column("Key", style="dim", width=16)
        abuse_table.add_column("Value", style="bold")
        
        if usage_type:
            abuse_table.add_row("Usage Type", usage_type)
        if abuse_velocity:
            vel_color = "green" if abuse_velocity == "none" else "yellow" if abuse_velocity == "low" else "red"
            abuse_table.add_row("Abuse Velocity", f"[{vel_color}]{abuse_velocity}[/{vel_color}]")
        if total_reports is not None:
            rep_color = "green" if total_reports == 0 else "yellow" if total_reports < 5 else "red"
            abuse_table.add_row("Abuse Reports", f"[{rep_color}]{total_reports}[/{rep_color}]")
        if last_seen:
            abuse_table.add_row("Last Seen", last_seen)
        
        console.print(Panel(abuse_table, title="[bold]Abuse Metrics[/bold]", border_style="magenta"))
    
    # =========================================================================
    # BLACKLIST STATUS
    # =========================================================================
    
    blacklists = info.get("blacklists", {})
    if blacklists:
        bl_table = Table(show_header=False, box=None, padding=(0, 2))
        bl_table.add_column("Blacklist", width=20)
        bl_table.add_column("Status", width=12)
        bl_table.add_column("Blacklist", width=20)
        bl_table.add_column("Status", width=12)
        
        bl_items = sorted(blacklists.items())
        for i in range(0, len(bl_items), 2):
            name1, listed1 = bl_items[i]
            status1 = "[red]! LISTED[/red]" if listed1 else "[green]+ Clean[/green]"
            if i + 1 < len(bl_items):
                name2, listed2 = bl_items[i + 1]
                status2 = "[red]! LISTED[/red]" if listed2 else "[green]+ Clean[/green]"
                bl_table.add_row(name1, status1, name2, status2)
            else:
                bl_table.add_row(name1, status1, "", "")
        
        console.print(Panel(bl_table, title="[bold]Blacklist Status[/bold]", border_style="red"))
    
    # =========================================================================
    # SOURCE RESULTS TABLE
    # =========================================================================
    
    source_table = Table(title="Source Results", show_header=True, header_style="bold")
    source_table.add_column("Source")
    source_table.add_column("Score", justify="center")
    source_table.add_column("Risk", justify="center")
    source_table.add_column("Status")
    
    for r in rep.results:
        if r.success:
            score = str(r.fraud_score) if r.fraud_score is not None else "-"
            risk_style = risk_colors.get(r.risk_level, "white")
            source_table.add_row(
                r.source,
                f"[{risk_style}]{score}[/{risk_style}]",
                f"[{risk_style}]{r.risk_level}[/{risk_style}]",
                "[green]OK[/green]"
            )
        else:
            source_table.add_row(
                r.source,
                "-",
                "-",
                f"[dim]{r.error or 'Failed'}[/dim]"
            )
    
    console.print(source_table)
    
    # API key hints
    missing_keys = []
    for r in rep.results:
        if not r.success and "No API key" in r.error:
            missing_keys.append(r.source)
    
    if missing_keys:
        console.print(f"\n[dim]Tip: Add API keys for more data: {', '.join(missing_keys)}[/dim]")
        console.print(f"[dim]     Config: {API_KEYS_FILE}[/dim]")


def _aggregate_info(results: list[ReputationResult]) -> dict[str, Any]:
    """Aggregate best info from all successful results."""
    info: dict[str, Any] = {"extra": {}}
    
    for r in results:
        if not r.success:
            continue
        
        # Take first non-empty value for each field
        for field in ["hostname", "isp", "org", "asn", "country", "city", "region"]:
            if not info.get(field) and getattr(r, field, ""):
                info[field] = getattr(r, field)
        
        # Aggregate boolean flags (True takes precedence)
        for field in ["is_vpn", "is_proxy", "is_tor", "is_datacenter"]:
            val = getattr(r, field, None)
            if val is True:
                info[field] = True
            elif val is False and field not in info:
                info[field] = False
        
        # Merge blacklists
        if r.blacklists:
            if "blacklists" not in info:
                info["blacklists"] = {}
            info["blacklists"].update(r.blacklists)
        
        # Merge extra fields (take first non-empty value for each)
        if r.extra:
            for key, val in r.extra.items():
                if key not in info["extra"] and val not in (None, "", [], {}):
                    info["extra"][key] = val
    
    return info


def configure_api_keys() -> None:
    """Interactive API key configuration."""
    from rich.prompt import Prompt
    
    console.print(Panel(
        "[bold]API Key Configuration[/bold]\n\n"
        "Optional API keys enable more detailed reputation data.\n"
        "Leave blank to skip. All have free tiers.",
        border_style="cyan",
    ))
    
    keys = load_api_keys()
    
    sources = [
        ("ipqualityscore", "IPQualityScore", "https://ipqualityscore.com/create-account"),
        ("abuseipdb", "AbuseIPDB", "https://abuseipdb.com/register"),
        ("virustotal", "VirusTotal", "https://virustotal.com/gui/join-us"),
        ("proxycheck", "ProxyCheck.io", "https://proxycheck.io/dashboard"),
        ("ipinfo", "IPinfo", "https://ipinfo.io/signup"),
    ]
    
    for key_name, display_name, signup_url in sources:
        current = keys.get(key_name, "")
        masked = f"{current[:8]}..." if len(current) > 8 else current
        
        console.print(f"\n[bold]{display_name}[/bold]")
        console.print(f"[dim]Sign up: {signup_url}[/dim]")
        if current:
            console.print(f"[dim]Current: {masked}[/dim]")
        
        new_key = Prompt.ask("API Key", default="", show_default=False)
        if new_key.strip():
            keys[key_name] = new_key.strip()
        elif not new_key and key_name in keys:
            # Keep existing key
            pass
    
    save_api_keys(keys)
    console.print(f"\n[green]✓ Saved to {API_KEYS_FILE}[/green]")


# =============================================================================
# CLI INTEGRATION
# =============================================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == "--configure":
            configure_api_keys()
        else:
            check_ip_reputation(sys.argv[1])
    else:
        console.print("[yellow]Usage: python -m proxy_tailscale.ip_reputation <IP>[/yellow]")
        console.print("[yellow]       python -m proxy_tailscale.ip_reputation --configure[/yellow]")
