#!/usr/bin/env python3
"""
Log Parser — Parses Splunk-exported event logs (CSV format).
Extracts key fields and displays them in a structured format.

Author: Vaibhav Joshi
"""

import sys
import pandas as pd
from rich.console import Console
from rich.table import Table

console = Console()


def load_logs(file_path):
    """Load CSV logs into a pandas DataFrame."""
    try:
        df = pd.read_csv(file_path)
        console.print(f"[green]✓[/green] Loaded {len(df)} events from {file_path}")
        return df
    except FileNotFoundError:
        console.print(f"[red]✗[/red] File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]✗[/red] Error loading file: {e}")
        sys.exit(1)


def display_summary(df):
    """Display a summary of the loaded events."""
    console.print("\n[bold cyan]📊 Event Summary[/bold cyan]")

    # Total events
    console.print(f"  Total events: [yellow]{len(df)}[/yellow]")

    # Unique EventCodes
    if "EventCode" in df.columns:
        codes = df["EventCode"].value_counts()
        console.print("\n  [bold]Events by EventCode:[/bold]")
        for code, count in codes.items():
            console.print(f"    → EventCode {code}: [yellow]{count}[/yellow]")


def display_events(df):
    """Display events in a formatted table."""
    table = Table(title="\n📋 Parsed Events", show_header=True, header_style="bold magenta")

    # Add columns
    for col in df.columns:
        table.add_column(col, overflow="fold")

    # Add rows (limit to 20 for readability)
    for _, row in df.head(20).iterrows():
        table.add_row(*[str(val) if pd.notna(val) else "" for val in row])

    console.print(table)


def main():
    if len(sys.argv) < 2:
        console.print("[yellow]Usage:[/yellow] python log_parser.py <path-to-csv>")
        sys.exit(1)

    file_path = sys.argv[1]

    console.print("[bold cyan]🔍 Log Parser — SOC Tool[/bold cyan]\n")

    df = load_logs(file_path)
    display_summary(df)
    display_events(df)


if __name__ == "__main__":
    main()
