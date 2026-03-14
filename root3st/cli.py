"""Root3st CLI -- the main entry point for the OSINT tool.

Usage examples:
    root3st ip 8.8.8.8
    root3st domain example.com
    root3st email user@example.com
    root3st username johndoe
    root3st phone "+1234567890"
    root3st name "John Doe"
    root3st social johndoe
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from root3st import __version__
from root3st.config import Config
from root3st.report import save_html, save_json

console = Console()


# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------

def _add_dict_to_tree(tree: Tree, data: dict[str, Any], max_depth: int = 4, depth: int = 0):
    """Recursively add dict entries to a Rich tree."""
    if depth >= max_depth:
        tree.add("[dim]...[/dim]")
        return
    for key, value in data.items():
        if isinstance(value, dict):
            branch = tree.add(f"[bold cyan]{key}[/bold cyan]")
            _add_dict_to_tree(branch, value, max_depth, depth + 1)
        elif isinstance(value, list):
            branch = tree.add(f"[bold cyan]{key}[/bold cyan] [dim]({len(value)} items)[/dim]")
            for i, item in enumerate(value[:20]):  # cap displayed items
                if isinstance(item, dict):
                    sub = branch.add(f"[dim]#{i}[/dim]")
                    _add_dict_to_tree(sub, item, max_depth, depth + 1)
                else:
                    branch.add(str(item))
            if len(value) > 20:
                branch.add(f"[dim]... and {len(value) - 20} more[/dim]")
        else:
            tree.add(f"[bold cyan]{key}:[/bold cyan] {value}")


def print_results(results: dict[str, Any]):
    """Print results as a Rich tree in the terminal."""
    target = results.get("target", "unknown")
    scan_type = results.get("type", "unknown")

    console.print()
    console.print(
        Panel(
            f"[bold green]Target:[/bold green] {target}  |  "
            f"[bold green]Type:[/bold green] {scan_type}",
            title="[bold bright_white]Root3st OSINT Results[/bold bright_white]",
            border_style="bright_blue",
        )
    )

    tree = Tree(f"[bold bright_white]{target}[/bold bright_white]", guide_style="bright_blue")
    display_data = {k: v for k, v in results.items() if k not in ("target", "type")}
    _add_dict_to_tree(tree, display_data)
    console.print(tree)
    console.print()


def print_username_table(results: dict[str, Any]):
    """Print username results as a table for better readability."""
    target = results.get("target", "unknown")
    found = results.get("found", [])
    not_found = results.get("not_found", [])

    console.print()
    console.print(
        Panel(
            f"[bold green]Username:[/bold green] {target}  |  "
            f"[bold green]Found:[/bold green] {len(found)} / {results.get('total_checked', 0)}",
            title="[bold bright_white]Root3st Username Search[/bold bright_white]",
            border_style="bright_blue",
        )
    )

    if found:
        table = Table(title="Profiles Found", box=box.ROUNDED, border_style="green")
        table.add_column("Platform", style="bold cyan")
        table.add_column("URL", style="bright_white")
        table.add_column("Status", justify="center")
        for entry in found:
            table.add_row(
                entry["platform"],
                entry["url"],
                "[bold green]FOUND[/bold green]",
            )
        console.print(table)

    if not_found:
        table = Table(title="Not Found", box=box.ROUNDED, border_style="dim")
        table.add_column("Platform", style="dim")
        table.add_column("URL", style="dim")
        for entry in not_found:
            table.add_row(entry["platform"], entry["url"])
        console.print(table)

    console.print()


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@click.group()
@click.option("--config", "-c", "config_path", type=click.Path(), default=None,
              help="Path to config YAML file.")
@click.option("--output", "-o", "output_dir", type=str, default=None,
              help="Output directory for reports.")
@click.option("--json-only", is_flag=True, default=False,
              help="Only output raw JSON to stdout (no Rich formatting).")
@click.version_option(__version__, prog_name="root3st")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None, output_dir: str | None, json_only: bool):
    """Root3st -- Comprehensive OSINT Reconnaissance Tool.

    Perform passive and active reconnaissance on IPs, domains, emails,
    usernames, phone numbers, names, and social media profiles.
    """
    ctx.ensure_object(dict)
    cfg = Config.load(Path(config_path) if config_path else None)
    if output_dir:
        cfg.output_dir = output_dir
    ctx.obj["config"] = cfg
    ctx.obj["json_only"] = json_only


def _handle_output(ctx: click.Context, results: dict[str, Any], use_table: bool = False):
    """Common output handler for all sub-commands."""
    cfg: Config = ctx.obj["config"]
    json_only: bool = ctx.obj["json_only"]

    if json_only:
        click.echo(json.dumps(results, indent=2, default=str))
    else:
        if use_table:
            print_username_table(results)
        else:
            print_results(results)

        # Save reports
        json_path = save_json(results, cfg.output_dir)
        html_path = save_html(results, cfg.output_dir)
        console.print(f"[dim]JSON report: {json_path}[/dim]")
        console.print(f"[dim]HTML report: {html_path}[/dim]")
        console.print()


@cli.command()
@click.argument("target")
@click.pass_context
def ip(ctx: click.Context, target: str):
    """Reconnaissance on an IP address.

    Performs geolocation, WHOIS, reverse DNS, port scanning,
    and optional Shodan/VirusTotal enrichment.
    """
    from root3st.utils import is_valid_ip

    if not is_valid_ip(target):
        console.print(f"[bold red]Error:[/bold red] '{target}' is not a valid IPv4 address.")
        sys.exit(1)

    console.print(f"[bold bright_blue]Scanning IP:[/bold bright_blue] {target} ...")
    from root3st.modules import ip_recon
    results = ip_recon.run(target, ctx.obj["config"])
    _handle_output(ctx, results)


@cli.command()
@click.argument("target")
@click.pass_context
def domain(ctx: click.Context, target: str):
    """Reconnaissance on a domain name.

    Performs DNS enumeration, WHOIS, SSL cert analysis, subdomain
    discovery, HTTP header analysis, and technology fingerprinting.
    """
    from root3st.utils import is_valid_domain

    if not is_valid_domain(target):
        console.print(f"[bold red]Error:[/bold red] '{target}' is not a valid domain.")
        sys.exit(1)

    console.print(f"[bold bright_blue]Scanning domain:[/bold bright_blue] {target} ...")
    from root3st.modules import domain_recon
    results = domain_recon.run(target, ctx.obj["config"])
    _handle_output(ctx, results)


@cli.command()
@click.argument("target")
@click.pass_context
def email(ctx: click.Context, target: str):
    """Reconnaissance on an email address.

    Checks MX records, email security (SPF/DMARC), Gravatar profile,
    HIBP breaches, and Hunter.io verification.
    """
    from root3st.utils import is_valid_email

    if not is_valid_email(target):
        console.print(f"[bold red]Error:[/bold red] '{target}' is not a valid email address.")
        sys.exit(1)

    console.print(f"[bold bright_blue]Scanning email:[/bold bright_blue] {target} ...")
    from root3st.modules import email_recon
    results = email_recon.run(target, ctx.obj["config"])
    _handle_output(ctx, results)


@cli.command()
@click.argument("target")
@click.pass_context
def username(ctx: click.Context, target: str):
    """Check a username across 30+ platforms.

    Performs concurrent HTTP checks to detect if a username is
    registered on popular social media and developer platforms.
    """
    console.print(f"[bold bright_blue]Checking username:[/bold bright_blue] {target} ...")
    from root3st.modules import username_recon
    results = username_recon.run(target, ctx.obj["config"])
    _handle_output(ctx, results, use_table=True)


@cli.command()
@click.argument("target")
@click.pass_context
def phone(ctx: click.Context, target: str):
    """Reconnaissance on a phone number.

    Analyses number format, identifies country of origin,
    and performs optional carrier lookups.
    """
    console.print(f"[bold bright_blue]Scanning phone:[/bold bright_blue] {target} ...")
    from root3st.modules import phone_recon
    results = phone_recon.run(target, ctx.obj["config"])
    _handle_output(ctx, results)


@cli.command()
@click.argument("target")
@click.pass_context
def name(ctx: click.Context, target: str):
    """Reconnaissance on a person's name.

    Generates targeted search dorks for Google, LinkedIn, Facebook,
    Twitter, GitHub, and more.
    """
    console.print(f"[bold bright_blue]Searching name:[/bold bright_blue] {target} ...")
    from root3st.modules import social_recon
    results = social_recon.run_name(target, ctx.obj["config"])
    _handle_output(ctx, results)


@cli.command()
@click.argument("target")
@click.pass_context
def social(ctx: click.Context, target: str):
    """Reconnaissance on a social media userid / handle.

    Fetches public profiles from GitHub, Reddit, GitLab,
    and generates search dorks for deeper investigation.
    """
    console.print(f"[bold bright_blue]Scanning social profile:[/bold bright_blue] {target} ...")
    from root3st.modules import social_recon
    results = social_recon.run_social(target, ctx.obj["config"])
    _handle_output(ctx, results)


# ---------------------------------------------------------------------------
# Full scan (combines multiple modules)
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("target")
@click.option("--type", "-t", "target_type", required=True,
              type=click.Choice(["ip", "domain", "email", "username", "phone", "name", "social"]),
              help="Target type to scan.")
@click.pass_context
def scan(ctx: click.Context, target: str, target_type: str):
    """Run a scan by specifying target and type explicitly.

    This is an alternative to the dedicated sub-commands.
    """
    # Map target_type to the appropriate command function
    command_map = {
        "ip": ip,
        "domain": domain,
        "email": email,
        "username": username,
        "phone": phone,
        "name": name,
        "social": social,
    }
    cmd = command_map.get(target_type)
    if cmd:
        ctx.invoke(cmd, target=target)


def main():
    """Entry point for the root3st CLI."""
    cli()


if __name__ == "__main__":
    main()
