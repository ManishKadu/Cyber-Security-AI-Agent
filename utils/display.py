"""
utils/display.py - Beautiful terminal output using Rich library
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.text import Text
from rich import box

console = Console()


def print_banner():
    """Print the application banner."""
    banner = """
 ██████╗██╗   ██╗██████╗ ███████╗██████╗     █████╗ ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗   ██╔══██╗██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝   ███████║██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗   ██╔══██║██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║   ██║  ██║██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚═╝
    Multi-Agent Cybersecurity System
    """
    console.print(Panel(banner, style="bold green", box=box.DOUBLE))


def print_agent_header(agent_name: str, icon: str = "🤖"):
    """Print a styled header for an agent's output."""
    console.print()
    console.print(Panel(
        f"{icon}  {agent_name}",
        style="bold cyan",
        box=box.ROUNDED,
        padding=(0, 2),
    ))


def print_finding(severity: str, title: str, details: str):
    """Print a security finding with color-coded severity."""
    color_map = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "green",
    }
    style = color_map.get(severity.upper(), "white")
    console.print(f"  [{style}][{severity.upper()}][/{style}] {title}")
    if details:
        console.print(f"         {details}", style="dim")


def print_result(text: str):
    """Print an AI-generated result as markdown."""
    console.print()
    console.print(Markdown(text))
    console.print()


def print_section(title: str):
    """Print a section divider."""
    console.print()
    console.rule(f"[bold]{title}[/bold]", style="cyan")
    console.print()


def print_status(message: str, style: str = "bold green"):
    """Print a status message."""
    console.print(f"  ✓ {message}", style=style)


def print_error(message: str):
    """Print an error message."""
    console.print(f"  ✗ {message}", style="bold red")
