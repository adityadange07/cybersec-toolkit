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


def run_module(choice: int):
    """Execute selected module."""
    results = {}

    try:
        if choice == 1:
            from modules.recon.port_scanner import PortScanner
            target = Prompt.ask("[cyan]Enter target (IP/hostname)[/cyan]")
            port_range = Prompt.ask("[cyan]Port range[/cyan]", default="1-1024")
            scan_type = Prompt.ask("[cyan]Scan type (tcp/syn)[/cyan]", default="tcp")
            scanner = PortScanner()
            results = scanner.execute(target, port_range=port_range, scan_type=scan_type)

        elif choice == 2:
            from modules.recon.subdomain_enum import SubdomainEnumerator
            target = Prompt.ask("[cyan]Enter domain[/cyan]")
            wordlist = Prompt.ask("[cyan]Wordlist path (optional)[/cyan]", default="")
            scanner = SubdomainEnumerator()
            results = scanner.execute(target, wordlist=wordlist if wordlist else None)

        elif choice == 3:
            from modules.recon.dns_enum import DNSEnumerator
            target = Prompt.ask("[cyan]Enter domain[/cyan]")
            scanner = DNSEnumerator()
            results = scanner.execute(target)

        elif choice == 4:
            from modules.recon.whois_lookup import WhoisLookup
            target = Prompt.ask("[cyan]Enter domain[/cyan]")
            scanner = WhoisLookup()
            results = scanner.execute(target)

        elif choice == 5:
            from modules.vuln_scanner.web_vuln_scanner import WebVulnScanner
            target = Prompt.ask("[cyan]Enter URL[/cyan]")
            scanner = WebVulnScanner()
            results = scanner.execute(target)

        elif choice == 6:
            from modules.vuln_scanner.sqli_scanner import SQLiScanner
            target = Prompt.ask("[cyan]Enter URL with parameters[/cyan]",
                              default="http://example.com/page?id=1")
            params = Prompt.ask("[cyan]Parameters to test (comma-separated)[/cyan]",
                              default="id")
            scanner = SQLiScanner()
            results = scanner.execute(target, params=params.split(','))

        elif choice == 7:
            from modules.vuln_scanner.xss_scanner import XSSScanner
            target = Prompt.ask("[cyan]Enter URL with parameters[/cyan]")
            params = Prompt.ask("[cyan]Parameters to test (comma-separated)[/cyan]",
                              default="q")
            scanner = XSSScanner()
            results = scanner.execute(target, params=params.split(','))

        elif choice == 8:
            from modules.network.packet_sniffer import PacketSniffer
            interface = Prompt.ask("[cyan]Network interface (leave empty for default)[/cyan]",
                                 default="")
            count = IntPrompt.ask("[cyan]Number of packets[/cyan]", default=50)
            bpf_filter = Prompt.ask("[cyan]BPF filter (optional)[/cyan]", default="")
            scanner = PacketSniffer()
            results = scanner.execute("local",
                                     interface=interface if interface else None,
                                     count=count,
                                     filter=bpf_filter if bpf_filter else "")

        elif choice == 9:
            from modules.network.packet_sniffer import ARPScanner
            target = Prompt.ask("[cyan]Enter network range[/cyan]",
                              default="192.168.1.0/24")
            scanner = ARPScanner()
            results = scanner.execute(target)

        elif choice == 10:
            from modules.mobile.apk_analyzer import APKAnalyzer
            target = Prompt.ask("[cyan]Enter APK file path[/cyan]")
            scanner = APKAnalyzer()
            results = scanner.execute(target)

        elif choice == 11:
            from modules.malware_analysis.static_analyzer import StaticMalwareAnalyzer
            target = Prompt.ask("[cyan]Enter file path[/cyan]")
            scanner = StaticMalwareAnalyzer()
            results = scanner.execute(target)

        elif choice == 12:
            from modules.forensics.metadata_extractor import MetadataExtractor
            target = Prompt.ask("[cyan]Enter file path[/cyan]")
            scanner = MetadataExtractor()
            results = scanner.execute(target)

        elif choice == 13:
            from modules.forensics.log_analyzer import LogAnalyzer
            target = Prompt.ask("[cyan]Enter log file path[/cyan]")
            scanner = LogAnalyzer()
            results = scanner.execute(target)

        elif choice == 14:
            from modules.password.hash_cracker import HashCracker
            target = Prompt.ask("[cyan]Enter hash to crack[/cyan]")
            hash_type = Prompt.ask("[cyan]Hash type[/cyan]",
                                 choices=["md5", "sha1", "sha256", "sha512"],
                                 default="md5")
            attack = Prompt.ask("[cyan]Attack type[/cyan]",
                              choices=["dictionary", "bruteforce"],
                              default="dictionary")
            wordlist = Prompt.ask("[cyan]Wordlist path[/cyan]",
                                default="wordlists/common.txt")
            scanner = HashCracker()
            results = scanner.execute(target, hash_type=hash_type,
                                     attack=attack, wordlist=wordlist)

        elif choice == 15:
            from modules.password.hash_cracker import HashIdentifier
            target = Prompt.ask("[cyan]Enter hash[/cyan]")
            scanner = HashIdentifier()
            results = scanner.execute(target)

        elif choice == 16:
            from modules.defensive.integrity_checker import IntegrityChecker
            target = Prompt.ask("[cyan]Enter directory path[/cyan]")
            action = Prompt.ask("[cyan]Action[/cyan]",
                              choices=["baseline", "check"],
                              default="check")
            scanner = IntegrityChecker()
            results = scanner.execute(target, action=action)

        elif choice == 17:
            from modules.reporting.report_generator import ReportGenerator
            target = Prompt.ask("[cyan]Target name for report[/cyan]")
            report_format = Prompt.ask("[cyan]Format[/cyan]",
                                     choices=["html", "pdf", "json"],
                                     default="html")
            results_file = Prompt.ask("[cyan]Results JSON file (optional)[/cyan]",
                                    default="")
            scan_results = {}
            if results_file and os.path.exists(results_file):
                with open(results_file, 'r') as f:
                    scan_results = json.load(f)

            generator = ReportGenerator()
            results = generator.execute(target, results=scan_results,
                                       format=report_format)

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Operation cancelled by user[/yellow]")
        return
    except ImportError as e:
        console.print(f"[red]❌ Missing dependency: {e}[/red]")
        console.print("[yellow]Install with: pip install -r requirements.txt[/yellow]")
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