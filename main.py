#!/usr/bin/env python3
"""
CyberSec Toolkit - Comprehensive Ethical Security Testing Tool
Author: Security Professional
License: MIT
WARNING: For authorized testing only!
"""

import sys
import os
import json
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, IntPrompt
    from rich.text import Text
    from rich import print as rprint
    import pyfiglet
except ImportError:
    print("Installing required packages...")
    os.system("pip install rich pyfiglet")
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, IntPrompt

from config.settings import config

console = Console()


def display_banner():
    """Display tool banner."""
    try:
        banner = pyfiglet.figlet_format("CyberSec", font="slant")
    except:
        banner = "=== CyberSec Toolkit ==="

    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print(Panel(
        "[bold green]Comprehensive Ethical Cybersecurity Toolkit[/bold green]\n"
        "[yellow]v1.0 - For Authorized Security Testing Only[/yellow]\n"
        "[dim]Bug Bounty | Pentesting | Forensics | Defense[/dim]",
        title="🛡️ CyberSec Toolkit",
        border_style="cyan"
    ))


def display_disclaimer():
    """Show legal disclaimer."""
    console.print(Panel(
        config.DISCLAIMER,
        title="⚠️  Legal Disclaimer",
        border_style="red"
    ))
    response = Prompt.ask(
        "[bold red]Do you agree to use this tool ethically and legally?[/bold red]",
        choices=["yes", "no"],
        default="no"
    )
    if response != "yes":
        console.print("[red]❌ You must agree to the terms to use this tool.[/red]")
        sys.exit(0)


def display_main_menu():
    """Display main menu."""
    table = Table(title="🔧 Module Selection", show_header=True,
                  header_style="bold magenta")
    table.add_column("No.", style="cyan", width=5)
    table.add_column("Module", style="green", width=25)
    table.add_column("Description", style="white")
    table.add_column("Category", style="yellow")

    modules = [
        ("1", "Port Scanner", "TCP/SYN port scanning with service detection", "Recon"),
        ("2", "Subdomain Enum", "Find subdomains using multiple sources", "Recon"),
        ("3", "DNS Enumeration", "DNS records, zone transfer, DNSSEC", "Recon"),
        ("4", "WHOIS Lookup", "Domain registration information", "Recon"),
        ("5", "Web Vuln Scanner", "Security headers, SSL, CORS, dirs", "Vuln Scan"),
        ("6", "SQL Injection", "SQLi detection (error/time/boolean)", "Vuln Scan"),
        ("7", "XSS Scanner", "Cross-site scripting detection", "Vuln Scan"),
        ("8", "Packet Sniffer", "Network packet capture & analysis", "Network"),
        ("9", "ARP Scanner", "Network host discovery", "Network"),
        ("10", "APK Analyzer", "Android app security analysis", "Mobile"),
        ("11", "Malware Analyzer", "Static malware analysis", "Malware"),
        ("12", "Metadata Extractor", "Extract file metadata/EXIF/GPS", "Forensics"),
        ("13", "Log Analyzer", "Security log analysis & attack detection", "Forensics"),
        ("14", "Hash Cracker", "Hash identification & cracking", "Password"),
        ("15", "Hash Identifier", "Identify hash types", "Password"),
        ("16", "Integrity Checker", "File integrity monitoring", "Defense"),
        ("17", "Generate Report", "Create HTML/PDF/JSON reports", "Reporting"),
        ("0", "Exit", "Exit the toolkit", "System"),
    ]

    for num, name, desc, cat in modules:
        table.add_row(num, name, desc, cat)

    console.print(table)


MODULE_CONFIG = {
    1: {
        "path": "modules.recon.port_scanner",
        "class": "PortScanner",
        "prompt": {
            "target": "Enter target (IP/hostname)",
            "port_range": "Port range",
            "scan_type": "Scan type (tcp/syn)"
        },
        "args": ["port_range", "scan_type"]
    },
    2: {
        "path": "modules.recon.subdomain_enum",
        "class": "SubdomainEnumerator",
        "prompt": {
            "target": "Enter domain"
        },
        "args": ["wordlist"]
    },
    3: {
        "path": "modules.recon.dns_enum",
        "class": "DNSEnumerator",
        "prompt": {
            "target": "Enter domain"
        }
    },
    4: {
        "path": "modules.recon.whois_lookup",
        "class": "WhoisLookup",
        "prompt": {
            "target": "Enter domain"
        }
    },
    5: {
        "path": "modules.vuln_scanner.web_vuln_scanner",
        "class": "WebVulnScanner",
        "prompt": {
            "target": "Enter URL"
        }
    },
    6: {
        "path": "modules.vuln_scanner.sqli_scanner",
        "class": "SQLiScanner",
        "prompt": {
            "target": "Enter URL with parameters",
            "params": "Parameters to test (comma-separated)"
        },
        "args": ["params"],
        "defaults": {"params": "id", "target": "http://example.com/page?id=1"}
    },
    7: {
        "path": "modules.vuln_scanner.xss_scanner",
        "class": "XSSScanner",
        "prompt": {
            "target": "Enter URL with parameters",
            "params": "Parameters to test (comma-separated)"
        },
        "args": ["params"],
        "defaults": {"params": "q"}
    },
    8: {
        "path": "modules.network.packet_sniffer",
        "class": "PacketSniffer",
        "prompt": {
            "interface": "Network interface (leave empty for default)",
            "count": "Number of packets",
            "filter": "BPF filter (optional)"
        },
        "args": ["interface", "count", "filter"],
        "defaults": {"interface": "", "count": 50, "filter": ""},
        "special": True
    },
    9: {
        "path": "modules.network.packet_sniffer",
        "class": "ARPScanner",
        "prompt": {
            "target": "Enter network range"
        },
        "defaults": {"target": "192.168.1.0/24"}
    },
    10: {
        "path": "modules.mobile.apk_analyzer",
        "class": "APKAnalyzer",
        "prompt": {
            "target": "Enter APK file path"
        }
    },
    11: {
        "path": "modules.malware_analysis.static_analyzer",
        "class": "StaticMalwareAnalyzer",
        "prompt": {
            "target": "Enter file path"
        }
    },
    12: {
        "path": "modules.forensics.metadata_extractor",
        "class": "MetadataExtractor",
        "prompt": {
            "target": "Enter file path"
        }
    },
    13: {
        "path": "modules.forensics.log_analyzer",
        "class": "LogAnalyzer",
        "prompt": {
            "target": "Enter log file path"
        }
    },
    14: {
        "path": "modules.password.hash_cracker",
        "class": "HashCracker",
        "prompt": {
            "target": "Enter hash to crack",
            "hash_type": "Hash type",
            "attack": "Attack type",
            "wordlist": "Wordlist path"
        },
        "args": ["hash_type", "attack", "wordlist"],
        "defaults": {"hash_type": "md5", "attack": "dictionary", "wordlist": "wordlists/common.txt"}
    },
    15: {
        "path": "modules.password.hash_cracker",
        "class": "HashIdentifier",
        "prompt": {
            "target": "Enter hash"
        }
    },
    16: {
        "path": "modules.defensive.integrity_checker",
        "class": "IntegrityChecker",
        "prompt": {
            "target": "Enter directory path",
            "action": "Action"
        },
        "args": ["action"],
        "defaults": {"action": "check"}
    },
    17: {
        "path": "modules.reporting.report_generator",
        "class": "ReportGenerator",
        "prompt": {
            "target": "Target name for report",
            "format": "Format"
        },
        "args": ["format", "results_file"],
        "defaults": {"format": "html"}
    }
}


def _execute_module(choice: int) -> dict:
    """Execute module using registry configuration."""
    if choice not in MODULE_CONFIG:
        return {"error": "Invalid module choice"}

    config = MODULE_CONFIG[choice]

    try:
        module = __import__(config["path"], fromlist=[config["class"]])
        scanner_class = getattr(module, config["class"])
        scanner = scanner_class()
    except (ImportError, AttributeError) as e:
        raise ImportError(f"Missing dependency: {e}")

    kwargs = {}
    
    if "special" in config and config["special"]:
        if choice == 8:
            interface = Prompt.ask("[cyan]" + config["prompt"]["interface"].replace("(", "") + "[/cyan]",
                                 default=config.get("defaults", {}).get("interface", ""))
            count = IntPrompt.ask("[cyan]" + config["prompt"]["count"].replace("(", "") + "[/cyan]",
                                default=config.get("defaults", {}).get("count", 50))
            bpf_filter = Prompt.ask("[cyan]" + config["prompt"]["filter"].replace("(", "") + "[/cyan]",
                                  default=config.get("defaults", {}).get("filter", ""))
            return scanner.execute("local",
                                 interface=interface if interface else None,
                                 count=count,
                                 filter=bpf_filter if bpf_filter else "")

    for key, prompt_text in config["prompt"].items():
        if key == "target":
            target = Prompt.ask(f"[cyan]{prompt_text}[/cyan]")
            kwargs["target"] = target
        elif key == "params":
            default_val = config.get("defaults", {}).get(key, "")
            params_str = Prompt.ask(f"[cyan]{prompt_text}[/cyan]", default=default_val)
            kwargs[key] = params_str.split(',')
        else:
            default_val = config.get("defaults", {}).get(key, "")
            value = Prompt.ask(f"[cyan]{prompt_text}[/cyan]", default=str(default_val))
            kwargs[key] = value

    return scanner.execute(**kwargs)


def run_module(choice: int):
    """Execute selected module."""
    results = {}

    try:
        results = _execute_module(choice)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Operation cancelled by user[/yellow]")
        return
    except Exception as e:
        console.print(f"[red]❌ Error: {str(e)}[/red]")
        import traceback
        traceback.print_exc()
        return

    # Display results
    if results:
        console.print("\n")
        console.print(Panel(
            json.dumps(results, indent=2, default=str)[:3000],
            title="📊 Results",
            border_style="green"
        ))

        # Save results
        save = Prompt.ask("[cyan]Save results to JSON?[/cyan]",
                         choices=["yes", "no"], default="yes")
        if save == "yes":
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"output/results_{timestamp}.json"
            os.makedirs("output", exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            console.print(f"[green]💾 Results saved to {output_file}[/green]")


def main():
    """Main application loop."""
    display_banner()
    display_disclaimer()

    while True:
        console.print("\n")
        display_main_menu()
        try:
            choice = IntPrompt.ask("\n[bold cyan]Select module[/bold cyan]",
                                   default=0)
        except KeyboardInterrupt:
            console.print("\n[yellow]👋 Goodbye![/yellow]")
            sys.exit(0)

        if choice == 0:
            console.print("[green]👋 Thanks for using CyberSec Toolkit! Stay ethical! 🛡️[/green]")
            sys.exit(0)

        if 1 <= choice <= 17:
            run_module(choice)
        else:
            console.print("[red]❌ Invalid choice. Try again.[/red]")


if __name__ == "__main__":
    main()