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
import time
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, IntPrompt
    from rich.text import Text
    from rich import print as rprint
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
    import pyfiglet
except ImportError:
    print("Installing required packages...")
    os.system("pip install rich pyfiglet")
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, IntPrompt
    from rich.text import Text
    from rich import print as rprint
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

from config.settings import config

console = Console()


def display_banner():
    """Display tool banner with enhanced visuals."""
    try:
        banner = pyfiglet.figlet_format("CyberSec", font="slant")
    except:
        banner = "=== CyberSec Toolkit ==="

    console.print(f"\n[bold cyan]{banner}[/bold cyan]")
    console.print(Panel(
        "[bold green]Comprehensive Ethical Cybersecurity Toolkit[/bold green]\n"
        "[yellow]v1.0 - For Authorized Security Testing Only[/yellow]\n"
        "[dim]Bug Bounty | Pentesting | Forensics | Defense[/dim]",
        title="🛡️ CyberSec Toolkit",
        border_style="cyan",
        padding=(1, 2)
    ))


def display_startup_info():
    """Display startup configuration and system info."""
    info_table = Table(
        title="🚀 Startup Information",
        show_header=False,
        border_style="blue",
        padding=(0, 2)
    )
    info_table.add_column("Setting", style="cyan", width=25)
    info_table.add_column("Value", style="white")
    
    info_table.add_row("Config Directory", str(Path.home() / ".config" / "cybersec"))
    info_table.add_row("Output Directory", "output/")
    info_table.add_row("Log Level", config.LOG_LEVEL)
    info_table.add_row("Max Threads", str(config.MAX_THREADS))
    info_table.add_row("Default Timeout", f"{config.DEFAULT_TIMEOUT}s")
    
    console.print(info_table)
    console.print()


def display_disclaimer():
    """Show legal disclaimer with better formatting."""
    console.print("\n" + "=" * 70)
    console.print(Panel(
        config.DISCLAIMER,
        title="⚠️  LEGAL DISCLAIMER",
        border_style="red",
        padding=(1, 2)
    ))
    console.print("=" * 70)
    
    response = Prompt.ask(
        "\n[bold red]🔒 Do you agree to use this tool ethically and legally?[/bold red]",
        choices=["yes", "no"],
        default="no"
    )
    
    if response != "yes":
        console.print("[red]❌ You must agree to the terms to use this tool.[/red]")
        sys.exit(0)
    
    console.print("[green]✅ Disclaimer accepted. Ready for secure testing.[/green]\n")


def display_main_menu():
    """Display enhanced main menu with better organization."""
    console.print("\n" + "=" * 70)
    
    # Category-based organization
    categories = {
        "🔍 Reconnaissance": [
            ("1", "Port Scanner", "TCP/SYN port scanning with service detection"),
            ("2", "Subdomain Enum", "Find subdomains using multiple sources"),
            ("3", "DNS Enumeration", "DNS records, zone transfer, DNSSEC"),
            ("4", "WHOIS Lookup", "Domain registration information"),
            ("18", "Service Enumerator", "Grab banners from discovered services"),
        ],
        "⚠️  Vulnerability Scanning": [
            ("5", "Web Vuln Scanner", "Security headers, SSL, CORS, dirs"),
            ("6", "SQL Injection", "SQLi detection (error/time/boolean)"),
            ("7", "XSS Scanner", "Cross-site scripting detection"),
            ("26", "DNS Vulnerability Scanner", "DNSSEC, zone transfer testing"),
        ],
        "🌐 Network Tools": [
            ("8", "Packet Sniffer", "Network packet capture & analysis"),
            ("9", "ARP Scanner", "Network host discovery"),
            ("22", "Network Mapper", "Visual network topology mapping"),
        ],
        "📱 Mobile Analysis": [
            ("10", "APK Analyzer", "Android app security analysis"),
            ("27", "Mobile Vulnerability Scanner", "Mobile app security testing"),
        ],
        "🦠 Malware Analysis": [
            ("11", "Malware Analyzer", "Static malware analysis"),
            ("28", "Dynamic Malware Analyzer", "Runtime malware analysis"),
        ],
        "🔍 Forensics": [
            ("12", "Metadata Extractor", "Extract file metadata/EXIF/GPS"),
            ("13", "Log Analyzer", "Security log analysis & attack detection"),
            ("29", "File Carver", "Recover deleted files from storage"),
        ],
        "🔑 Password Attacks": [
            ("14", "Hash Cracker", "Hash identification & cracking"),
            ("15", "Hash Identifier", "Identify hash types"),
            ("30", "Password Generator", "Generate secure passwords"),
        ],
        "🛡️ Defense & Monitoring": [
            ("16", "Integrity Checker", "File integrity monitoring"),
            ("31", "IDS/IPS", "Network intrusion detection system"),
            ("32", "Threat Intelligence", "Threat intelligence integration"),
        ],
        "📄 Reporting": [
            ("17", "Generate Report", "Create HTML/PDF/JSON reports"),
            ("33", "Template Manager", "Manage report templates"),
        ],
        "⚙️  System": [
            ("0", "Exit", "Exit the toolkit"),
            ("34", "Settings", "Configure application settings"),
            ("35", "Help", "Show help information"),
        ]
    }
    
    # Display each category
    for category, modules in categories.items():
        cat_table = Table(
            title=category,
            show_header=True,
            header_style="bold white",
            border_style="green" if "Recon" in category else "blue" if "Vulnerability" in category else "magenta"
        )
        cat_table.add_column("No.", style="cyan", width=3)
        cat_table.add_column("Module", style="green", width=20)
        cat_table.add_column("Description", style="white")
        
        for num, name, desc in modules:
            cat_table.add_row(num, name, desc)
        
        console.print(cat_table)
        console.print()
    
    console.print("=" * 70)


def display_module_progress(operation: str, target: str = None):
    """Display progress indicators for long-running operations."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:.0f}%(\u2005[bold magenta]{task.completed}/{task.total}[/bold magenta])"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task(f"[cyan]{operation}", total=100)
        
        # Simulate progress for demo
        for i in range(101):
            time.sleep(0.01)
            progress.update(task, completed=i)
            if target and i == 50:
                console.print(f"[dim]Target: {target}[/dim]")


def run_module(choice: int):
    """Execute selected module with enhanced UI feedback."""
    from main import _execute_module, MODULE_CONFIG
    
    module_info = MODULE_CONFIG.get(choice)
    if not module_info:
        console.print("[red]❌ Invalid module choice.[/red]")
        return
    
    module_name = module_info.get("class", "Unknown Module")
    
    console.print("\n" + "=" * 70)
    console.print(Panel(
        f"🔧 Executing Module: [bold cyan]{module_name}[/]\n"
        f"📝 Description: {module_info.get('description', 'No description available')}\n"
        f"🎯 Configuration loaded successfully.",
        title="🚀 Module Execution Started",
        border_style="blue",
        padding=(1, 2)
    ))
    console.print("=" * 70)
    
    # Show progress bar
    display_module_progress("Running Module", f"Module {choice}")
    
    try:
        results = _execute_module(choice)
        
        if results:
            console.print("\n" + "=" * 70)
            console.print(Panel(
                json.dumps(results, indent=2, default=str)[:2000],
                title="📊 Module Results",
                border_style="green",
                padding=(1, 2)
            ))
            console.print("=" * 70)
            
            # Save results with enhanced feedback
            save = Prompt.ask(
                "[bold green]💾 Save results to JSON?[/bold green]",
                choices=["yes", "no"], default="yes"
            )
            if save == "yes":
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_dir = Path("output")
                output_dir.mkdir(exist_ok=True)
                output_file = output_dir / f"results_{timestamp}.json"
                
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                
                console.print(f"\n[green]✅ Results saved to: {output_file}[/green]")
                console.print(f"📁 View results: ls -la {output_dir}/")
        else:
            console.print("\n[yellow]⚠️ No results returned from module.[/yellow]")
            
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Operation cancelled by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]❌ Error in module {module_name}: {str(e)}[/red]")
        import traceback
        traceback.print_exc()


def main():
    """Enhanced main application loop with improved UX."""
    display_banner()
    display_startup_info()
    display_disclaimer()
    
    while True:
        try:
            display_main_menu()
            choice = IntPrompt.ask(
                "\n[bold cyan]🎯 Select module number[/bold cyan]",
                default=0
            )
            
            if choice == 0:
                console.print("\n" + "=" * 70)
                console.print("[green]👋 Thanks for using CyberSec Toolkit! Stay ethical! 🛡️[/green]")
                console.print("=" * 70)
                sys.exit(0)
            
            if 1 <= choice <= 35:
                run_module(choice)
            else:
                console.print(f"\n[red]❌ Module {choice} does not exist. Please choose 0-35.[/red]")
                continue
                
        except KeyboardInterrupt:
            console.print("\n\n[yellow]👋 Goodbye! Keyboard interrupt received.[/yellow]")
            sys.exit(0)
        except Exception as e:
            console.print(f"\n[red]❌ Unexpected error: {str(e)}[/red]")
            continue


if __name__ == "__main__":
    main()