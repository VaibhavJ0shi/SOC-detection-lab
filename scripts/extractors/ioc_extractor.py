"""
IOC Extractor — Extracts Indicators of Compromise from log files.
Supports: IPv4 addresses, MD5/SHA1/SHA256 hashes, usernames, domains, URLs.

Author: Vaibhav Joshi
"""

import sys
import re
from rich.console import Console
from rich.table import Table

console = Console()


# Regex patterns for different IOC types
PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "url": r"https?://[^\s]+",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "username": r"Account_Name=([A-Za-z0-9._-]+)",
}


def extract_iocs(text):
    """Extract all IOC types from the given text."""
    iocs = {}

    for name, pattern in PATTERNS.items():
        matches = set(re.findall(pattern, text))
        if matches:
            iocs[name] = sorted(matches)

    return iocs


def display_iocs(iocs):
    """Display extracted IOCs in a formatted way."""
    if not iocs:
        console.print("[yellow]⚠ No IOCs found.[/yellow]")
        return

    table = Table(title="🎯 Extracted IOCs", show_header=True, header_style="bold magenta")
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("Value", style="yellow")
    table.add_column("Count", justify="right", style="green")

    for ioc_type, values in iocs.items():
        for val in values:
            table.add_row(ioc_type.upper(), val, str(len(values)))

    console.print(table)


def main():
    if len(sys.argv) < 2:
        console.print("[yellow]Usage:[/yellow] python ioc_extractor.py <path-to-file>")
        sys.exit(1)

    file_path = sys.argv[1]

    console.print("[bold cyan]🔍 IOC Extractor — SOC Tool[/bold cyan]\n")

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except FileNotFoundError:
        console.print(f"[red]✗[/red] File not found: {file_path}")
        sys.exit(1)

    console.print(f"[green]✓[/green] Loaded file: {file_path}")
    console.print(f"[green]✓[/green] File size: {len(text)} characters\n")

    iocs = extract_iocs(text)
    display_iocs(iocs)

    # Summary
    total = sum(len(v) for v in iocs.values())
    console.print(f"\n[bold green]Total unique IOCs found: {total}[/bold green]")


if __name__ == "__main__":
    main()
