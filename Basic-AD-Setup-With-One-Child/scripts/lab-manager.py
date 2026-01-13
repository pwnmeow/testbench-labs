#!/usr/bin/env python3
"""
Akatsuki Lab Manager
====================
A CLI tool for managing Windows AD lab environments with Vagrant + VMware Workstation.

Features:
- Download Windows ISOs from massgrave.dev
- Build Vagrant boxes using Packer
- Manage lab lifecycle (start, stop, destroy)
"""

import os
import sys
import subprocess
import shutil
import glob
import hashlib
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, DownloadColumn, TransferSpeedColumn
    import requests
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Note: Install 'rich' and 'requests' for better experience: pip install rich requests")

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
ISO_DIR = PROJECT_ROOT / "iso"
BOXES_DIR = PROJECT_ROOT / "boxes"
PACKER_DIR = PROJECT_ROOT / "packer"
VAGRANT_DIR = PROJECT_ROOT / "vagrant"

# Console for rich output
console = Console() if RICH_AVAILABLE else None

# ISO download URLs from massgrave.dev
# These are the direct download links - update as needed
ISO_OPTIONS = {
    "server": {
        "Windows Server 2025 (Latest)": {
            "url": "https://go.microsoft.com/fwlink/?linkid=2195686",
            "filename": "windows_server_2025.iso",
            "manual_url": "https://massgrave.dev/windows_server_links"
        },
        "Windows Server 2022 (Recommended)": {
            "url": "https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US",
            "filename": "windows_server_2022.iso",
            "manual_url": "https://massgrave.dev/windows_server_links"
        },
        "Windows Server 2019": {
            "url": "https://go.microsoft.com/fwlink/p/?LinkID=2195167&clcid=0x409&culture=en-us&country=US",
            "filename": "windows_server_2019.iso",
            "manual_url": "https://massgrave.dev/windows_server_links"
        }
    },
    "client": {
        "Windows 11 25H2 (Latest)": {
            "url": "https://go.microsoft.com/fwlink/?linkid=2156292",
            "filename": "windows_11_25h2.iso",
            "manual_url": "https://massgrave.dev/windows_11_links"
        },
        "Windows 11 24H2 (Recommended)": {
            "url": "https://go.microsoft.com/fwlink/?linkid=2156292",
            "filename": "windows_11_24h2.iso",
            "manual_url": "https://massgrave.dev/windows_11_links"
        },
        "Windows 11 23H2": {
            "url": "https://go.microsoft.com/fwlink/?linkid=2156292",
            "filename": "windows_11_23h2.iso",
            "manual_url": "https://massgrave.dev/windows_11_links"
        }
    }
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def check_vmware_network() -> bool:
    """Check if VMware vmnet8 (NAT) network is configured."""
    try:
        # Check for vmnet8 adapter in ipconfig output
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            shell=True
        )
        return "VMnet8" in result.stdout
    except Exception:
        return False


def configure_vmware_network() -> bool:
    """Automatically configure VMware virtual networks by restoring defaults."""
    if RICH_AVAILABLE:
        console.print("[cyan]Configuring VMware virtual networks...[/cyan]")
    else:
        print("Configuring VMware virtual networks...")

    # Find VMware Workstation installation
    vmware_paths = [
        Path(r"C:\Program Files (x86)\VMware\VMware Workstation"),
        Path(r"C:\Program Files\VMware\VMware Workstation"),
    ]

    vmnetcfg_exe = None
    for vmware_path in vmware_paths:
        # Try different possible names for the network config utility
        for exe_name in ["vmnetcfg.exe", "vmware-netcfg.exe"]:
            candidate = vmware_path / exe_name
            if candidate.exists():
                vmnetcfg_exe = candidate
                break
        if vmnetcfg_exe:
            break

    if vmnetcfg_exe:
        # Try running the network config utility
        try:
            if RICH_AVAILABLE:
                console.print(f"[dim]Running {vmnetcfg_exe.name}...[/dim]")
            result = subprocess.run(
                [str(vmnetcfg_exe), "-r"],  # -r flag restores defaults
                capture_output=True,
                timeout=60
            )
            if result.returncode == 0:
                if RICH_AVAILABLE:
                    console.print("[green]VMware networks configured successfully![/green]")
                else:
                    print("VMware networks configured successfully!")
                return True
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[yellow]Network config utility failed: {e}[/yellow]")

    # Alternative: Use vnetlib to configure networks
    vnetlib_paths = [
        Path(r"C:\Program Files (x86)\VMware\VMware Workstation\vnetlib64.exe"),
        Path(r"C:\Program Files\VMware\VMware Workstation\vnetlib64.exe"),
        Path(r"C:\Program Files (x86)\VMware\VMware Workstation\vnetlib.exe"),
    ]

    vnetlib_exe = None
    for path in vnetlib_paths:
        if path.exists():
            vnetlib_exe = path
            break

    if vnetlib_exe:
        try:
            if RICH_AVAILABLE:
                console.print("[dim]Configuring vmnet8 NAT network...[/dim]")

            # Stop networking services first
            subprocess.run(["net", "stop", "VMnetDHCP"], capture_output=True, shell=True)
            subprocess.run(["net", "stop", "VMware NAT Service"], capture_output=True, shell=True)

            # Configure vmnet8 as NAT
            commands = [
                [str(vnetlib_exe), "--", "add", "adapter", "vmnet8"],
                [str(vnetlib_exe), "--", "set", "vnet", "vmnet8", "mask", "255.255.255.0"],
                [str(vnetlib_exe), "--", "set", "vnet", "vmnet8", "addr", "192.168.56.0"],
                [str(vnetlib_exe), "--", "set", "adapter", "vmnet8", "addr", "192.168.56.1"],
                [str(vnetlib_exe), "--", "add", "nat", "vmnet8"],
                [str(vnetlib_exe), "--", "add", "dhcp", "vmnet8"],
                [str(vnetlib_exe), "--", "update", "dhcp", "vmnet8"],
                [str(vnetlib_exe), "--", "update", "nat", "vmnet8"],
            ]

            for cmd in commands:
                subprocess.run(cmd, capture_output=True, timeout=30)

            # Restart services
            subprocess.run(["net", "start", "VMnetDHCP"], capture_output=True, shell=True)
            subprocess.run(["net", "start", "VMware NAT Service"], capture_output=True, shell=True)

            if RICH_AVAILABLE:
                console.print("[green]VMware vmnet8 configured![/green]")
            else:
                print("VMware vmnet8 configured!")
            return True

        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"[yellow]vnetlib configuration failed: {e}[/yellow]")

    # If all automatic methods fail, provide manual instructions
    if RICH_AVAILABLE:
        console.print("\n[yellow]Automatic VMware network configuration failed.[/yellow]")
        console.print("[bold]Please configure manually:[/bold]")
        console.print("  1. Open VMware Workstation as Administrator")
        console.print("  2. Go to Edit → Virtual Network Editor")
        console.print("  3. Click 'Restore Defaults' (requires admin)")
        console.print("  4. Click Apply and OK")
        console.print("\n[dim]This creates vmnet8 (NAT) which Packer needs.[/dim]")
        Prompt.ask("\nPress Enter after configuring VMware networking")
    else:
        print("\nAutomatic VMware network configuration failed.")
        print("Please configure manually:")
        print("  1. Open VMware Workstation as Administrator")
        print("  2. Go to Edit → Virtual Network Editor")
        print("  3. Click 'Restore Defaults' (requires admin)")
        print("  4. Click Apply and OK")
        input("\nPress Enter after configuring VMware networking")

    # Re-check after manual configuration
    return check_vmware_network()


def check_packer_plugins() -> bool:
    """Check if required Packer plugins are installed."""
    plugin_dir = Path.home() / "AppData" / "Roaming" / "packer.d" / "plugins"

    # Check for vmware and vagrant plugins
    vmware_installed = False
    vagrant_installed = False

    if plugin_dir.exists():
        for item in plugin_dir.rglob("*"):
            if "vmware" in item.name.lower():
                vmware_installed = True
            if "vagrant" in item.name.lower():
                vagrant_installed = True

    return vmware_installed and vagrant_installed


def install_packer_plugins() -> bool:
    """Install required Packer plugins using packer init."""
    if RICH_AVAILABLE:
        console.print("[cyan]Installing Packer plugins...[/cyan]")
    else:
        print("Installing Packer plugins...")

    success = True
    for hcl_file in ["windows-server-2022.pkr.hcl", "windows-11.pkr.hcl"]:
        hcl_path = PACKER_DIR / hcl_file
        if hcl_path.exists():
            if RICH_AVAILABLE:
                console.print(f"[dim]Running packer init for {hcl_file}...[/dim]")
            result = subprocess.run(
                ["packer", "init", str(hcl_path)],
                capture_output=True,
                text=True,
                cwd=str(PACKER_DIR)
            )
            if result.returncode != 0:
                if RICH_AVAILABLE:
                    console.print(f"[red]Failed to init {hcl_file}: {result.stderr}[/red]")
                else:
                    print(f"Failed to init {hcl_file}: {result.stderr}")
                success = False
            else:
                if RICH_AVAILABLE:
                    console.print(f"[green]Plugins installed for {hcl_file}[/green]")

    return success


def preflight_checks() -> bool:
    """Run all pre-flight checks before building. Returns True if all checks pass."""
    all_passed = True

    if RICH_AVAILABLE:
        console.print("\n[bold cyan]Running pre-flight checks...[/bold cyan]\n")
    else:
        print("\nRunning pre-flight checks...\n")

    # Check 1: Packer installed
    if RICH_AVAILABLE:
        console.print("[dim]Checking Packer installation...[/dim]")
    if not shutil.which("packer"):
        if RICH_AVAILABLE:
            console.print("[red]✗ Packer not found![/red]")
            console.print("  Visit: https://developer.hashicorp.com/packer/downloads")
        else:
            print("✗ Packer not found!")
            print("  Visit: https://developer.hashicorp.com/packer/downloads")
        return False
    if RICH_AVAILABLE:
        console.print("[green]✓ Packer installed[/green]")
    else:
        print("✓ Packer installed")

    # Check 2: Packer plugins
    if RICH_AVAILABLE:
        console.print("[dim]Checking Packer plugins...[/dim]")
    if not check_packer_plugins():
        if RICH_AVAILABLE:
            console.print("[yellow]⚠ Packer plugins not installed, installing now...[/yellow]")
        else:
            print("⚠ Packer plugins not installed, installing now...")
        if not install_packer_plugins():
            if RICH_AVAILABLE:
                console.print("[red]✗ Failed to install Packer plugins[/red]")
            else:
                print("✗ Failed to install Packer plugins")
            all_passed = False
        else:
            if RICH_AVAILABLE:
                console.print("[green]✓ Packer plugins installed[/green]")
            else:
                print("✓ Packer plugins installed")
    else:
        if RICH_AVAILABLE:
            console.print("[green]✓ Packer plugins installed[/green]")
        else:
            print("✓ Packer plugins installed")

    # Check 3: VMware Workstation installed
    if RICH_AVAILABLE:
        console.print("[dim]Checking VMware Workstation...[/dim]")
    vmware_installed = any([
        Path(r"C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe").exists(),
        Path(r"C:\Program Files\VMware\VMware Workstation\vmware.exe").exists(),
        shutil.which("vmware"),
    ])
    if not vmware_installed:
        if RICH_AVAILABLE:
            console.print("[red]✗ VMware Workstation not found![/red]")
            console.print("  Please install VMware Workstation Pro")
        else:
            print("✗ VMware Workstation not found!")
            print("  Please install VMware Workstation Pro")
        all_passed = False
    else:
        if RICH_AVAILABLE:
            console.print("[green]✓ VMware Workstation installed[/green]")
        else:
            print("✓ VMware Workstation installed")

    if all_passed:
        if RICH_AVAILABLE:
            console.print("\n[bold green]All pre-flight checks passed![/bold green]\n")
        else:
            print("\nAll pre-flight checks passed!\n")

    return all_passed

def print_banner():
    banner = """
    ___    __         __             __   _    __          __
   /   |  / /______ _/ /________  __/ /__(_)  / /   ____ _/ /_
  / /| | / //_/ __ `/ __/ ___/ / / / //_/ /  / /   / __ `/ __ \\
 / ___ |/ ,< / /_/ / /_(__  ) /_/ / ,< / /  / /___/ /_/ / /_/ /
/_/  |_/_/|_|\\__,_/\\__/____/\\__,_/_/|_/_/  /_____/\\__,_/_.___/

    AD Lab Manager - akatsuki.local
    """
    if RICH_AVAILABLE:
        console.print(Panel(banner, style="red bold"))
    else:
        print(banner)

def get_existing_isos() -> dict:
    """Find existing ISOs in the iso directory."""
    existing = {"server": [], "client": [], "unknown": []}

    if not ISO_DIR.exists():
        return existing

    for iso_file in ISO_DIR.glob("*.iso"):
        name = iso_file.name.lower()
        if "server" in name:
            existing["server"].append(iso_file)
        elif "windows" in name or "win" in name:
            existing["client"].append(iso_file)
        else:
            existing["unknown"].append(iso_file)

    return existing

def get_all_isos() -> list:
    """Get all ISO files in the iso directory."""
    if not ISO_DIR.exists():
        return []
    return list(ISO_DIR.glob("*.iso"))

def select_custom_iso(iso_type: str) -> Optional[Path]:
    """Let user select a custom ISO from the iso folder."""
    all_isos = get_all_isos()

    if not all_isos:
        if RICH_AVAILABLE:
            console.print(f"[yellow]No ISO files found in {ISO_DIR}[/yellow]")
            console.print("Please copy your ISO files to this directory first.")
        else:
            print(f"No ISO files found in {ISO_DIR}")
            print("Please copy your ISO files to this directory first.")
        return None

    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]Select {iso_type.capitalize()} ISO from available files:[/bold cyan]")
        for i, iso in enumerate(all_isos, 1):
            size = iso.stat().st_size / (1024**3)
            console.print(f"  [{i}] {iso.name} ({size:.2f} GB)")
        console.print(f"  [0] Cancel")

        choice = Prompt.ask("Select ISO", default="1")
    else:
        print(f"\nSelect {iso_type.capitalize()} ISO from available files:")
        for i, iso in enumerate(all_isos, 1):
            size = iso.stat().st_size / (1024**3)
            print(f"  [{i}] {iso.name} ({size:.2f} GB)")
        print(f"  [0] Cancel")
        choice = input("Select ISO [1]: ").strip() or "1"

    try:
        idx = int(choice)
        if idx == 0:
            return None
        if 1 <= idx <= len(all_isos):
            return all_isos[idx - 1]
    except ValueError:
        pass

    return all_isos[0] if all_isos else None

def display_iso_status():
    """Display status of ISOs in the iso directory."""
    existing = get_existing_isos()

    if RICH_AVAILABLE:
        table = Table(title="ISO Status")
        table.add_column("Type", style="cyan")
        table.add_column("File", style="green")
        table.add_column("Size", style="yellow")

        for iso_type, files in existing.items():
            if files:
                for f in files:
                    size = f.stat().st_size / (1024**3)  # GB
                    table.add_row(iso_type.capitalize(), f.name, f"{size:.2f} GB")
            else:
                table.add_row(iso_type.capitalize(), "Not found", "-")

        console.print(table)
    else:
        print("\n=== ISO Status ===")
        for iso_type, files in existing.items():
            if files:
                for f in files:
                    size = f.stat().st_size / (1024**3)
                    print(f"  {iso_type.capitalize()}: {f.name} ({size:.2f} GB)")
            else:
                print(f"  {iso_type.capitalize()}: Not found")

def select_iso(iso_type: str) -> tuple:
    """Interactive ISO selection menu.

    Returns: (selection_type, value) where:
        - ("download", option_name) for massgrave download
        - ("custom", Path) for custom ISO selection
        - ("skip", None) to skip
    """
    options = ISO_OPTIONS[iso_type]
    option_list = list(options.keys())

    # Check for existing ISOs
    all_isos = get_all_isos()
    has_existing = len(all_isos) > 0

    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan]Select {iso_type.capitalize()} ISO:[/bold cyan]")
        console.print(f"\n  [bold]Download from massgrave.dev:[/bold]")
        for i, opt in enumerate(option_list, 1):
            marker = "[yellow](default)[/yellow]" if "Recommended" in opt else ""
            console.print(f"    [{i}] {opt} {marker}")

        if has_existing:
            console.print(f"\n  [bold]Use existing ISO:[/bold]")
            console.print(f"    [c] Choose from {len(all_isos)} ISO(s) in /iso folder")

        console.print(f"\n    [0] Skip")

        default = "2" if len(option_list) >= 2 else "1"
        choice = Prompt.ask("Select option", default=default)
    else:
        print(f"\nSelect {iso_type.capitalize()} ISO:")
        print(f"\n  Download from massgrave.dev:")
        for i, opt in enumerate(option_list, 1):
            marker = "(default)" if "Recommended" in opt else ""
            print(f"    [{i}] {opt} {marker}")

        if has_existing:
            print(f"\n  Use existing ISO:")
            print(f"    [c] Choose from {len(all_isos)} ISO(s) in /iso folder")

        print(f"\n    [0] Skip")
        choice = input("Select option [2]: ").strip() or "2"

    # Handle custom ISO selection
    if choice.lower() == 'c':
        custom_iso = select_custom_iso(iso_type)
        if custom_iso:
            return ("custom", custom_iso)
        return ("skip", None)

    try:
        idx = int(choice)
        if idx == 0:
            return ("skip", None)
        if 1 <= idx <= len(option_list):
            return ("download", option_list[idx - 1])
    except ValueError:
        pass

    # Default to recommended
    default_opt = option_list[1] if len(option_list) >= 2 else option_list[0]
    return ("download", default_opt)

def download_iso(iso_type: str, selected_option: str):
    """Download or guide user to download the ISO."""
    iso_info = ISO_OPTIONS[iso_type][selected_option]
    target_path = ISO_DIR / iso_info["filename"]

    if target_path.exists():
        if RICH_AVAILABLE:
            console.print(f"[green]ISO already exists:[/green] {target_path.name}")
            if not Confirm.ask("Re-download?", default=False):
                return
        else:
            print(f"ISO already exists: {target_path.name}")
            if input("Re-download? [y/N]: ").lower() != 'y':
                return

    # Check for existing ISOs that could be used
    existing = get_existing_isos()
    if existing[iso_type]:
        if RICH_AVAILABLE:
            console.print(f"\n[yellow]Found existing {iso_type} ISO(s):[/yellow]")
            for i, f in enumerate(existing[iso_type], 1):
                console.print(f"  [{i}] {f.name}")
            console.print(f"  [0] Download new")

            use_existing = Prompt.ask("Use existing ISO?", default="0")
            if use_existing != "0":
                try:
                    idx = int(use_existing) - 1
                    if 0 <= idx < len(existing[iso_type]):
                        # Create symlink or copy with expected name
                        src = existing[iso_type][idx]
                        if src.name != iso_info["filename"]:
                            target_path.symlink_to(src)
                            console.print(f"[green]Linked {src.name} -> {iso_info['filename']}[/green]")
                        return
                except (ValueError, IndexError):
                    pass

    # Attempt download
    if RICH_AVAILABLE:
        console.print(f"\n[cyan]Downloading {selected_option}...[/cyan]")
        console.print(f"[dim]URL: {iso_info['url']}[/dim]")
    else:
        print(f"\nDownloading {selected_option}...")
        print(f"URL: {iso_info['url']}")

    try:
        # Try to download with requests
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
            ) as progress:
                response = requests.get(iso_info['url'], stream=True, allow_redirects=True, timeout=30)

                # Check if we got an actual ISO or a redirect page
                content_type = response.headers.get('content-type', '')
                if 'text/html' in content_type:
                    raise Exception("Got HTML page instead of ISO - manual download required")

                total_size = int(response.headers.get('content-length', 0))
                task = progress.add_task(f"Downloading {iso_info['filename']}", total=total_size)

                with open(target_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                        progress.update(task, advance=len(chunk))

            console.print(f"[green]Downloaded successfully:[/green] {target_path}")
        else:
            response = requests.get(iso_info['url'], stream=True, allow_redirects=True, timeout=30)
            content_type = response.headers.get('content-type', '')
            if 'text/html' in content_type:
                raise Exception("Got HTML page instead of ISO - manual download required")

            with open(target_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Downloaded successfully: {target_path}")

    except Exception as e:
        if RICH_AVAILABLE:
            console.print(f"\n[yellow]Automatic download not available.[/yellow]")
            console.print(f"[red]Reason: {e}[/red]")
            console.print(f"\n[bold]Please download manually:[/bold]")
            console.print(f"  1. Visit: [link]{iso_info['manual_url']}[/link]")
            console.print(f"  2. Download the ISO for: {selected_option}")
            console.print(f"  3. Save to: [cyan]{ISO_DIR}[/cyan]")
            console.print(f"  4. Rename to: [cyan]{iso_info['filename']}[/cyan]")
            Prompt.ask("\nPress Enter when done")
        else:
            print(f"\nAutomatic download not available: {e}")
            print(f"\nPlease download manually:")
            print(f"  1. Visit: {iso_info['manual_url']}")
            print(f"  2. Download the ISO for: {selected_option}")
            print(f"  3. Save to: {ISO_DIR}")
            print(f"  4. Rename to: {iso_info['filename']}")
            input("\nPress Enter when done")

def set_iso_for_build(iso_type: str, iso_path: Path):
    """Register an ISO for use in builds by creating a symlink with expected name."""
    if iso_type == "server":
        target_name = "windows_server_2022.iso"
    else:
        target_name = "windows_11_24h2.iso"

    target_path = ISO_DIR / target_name

    # Remove existing symlink if present
    if target_path.is_symlink():
        target_path.unlink()

    # If source has different name, create symlink
    if iso_path.name != target_name:
        try:
            target_path.symlink_to(iso_path)
            if RICH_AVAILABLE:
                console.print(f"[green]Linked:[/green] {iso_path.name} -> {target_name}")
            else:
                print(f"Linked: {iso_path.name} -> {target_name}")
        except OSError:
            # On Windows, symlinks may fail - copy instead
            if RICH_AVAILABLE:
                console.print(f"[yellow]Note: Using {iso_path.name} directly[/yellow]")
            else:
                print(f"Note: Using {iso_path.name} directly")

def menu_download_isos():
    """Download ISOs menu."""
    clear_screen()
    print_banner()

    if RICH_AVAILABLE:
        console.print("\n[bold magenta]=== ISO Manager ===[/bold magenta]\n")
    else:
        print("\n=== ISO Manager ===\n")

    display_iso_status()

    # Server ISO
    selection_type, value = select_iso("server")
    if selection_type == "download":
        download_iso("server", value)
    elif selection_type == "custom":
        set_iso_for_build("server", value)
        if RICH_AVAILABLE:
            console.print(f"[green]Using custom Server ISO:[/green] {value.name}")
        else:
            print(f"Using custom Server ISO: {value.name}")

    # Client ISO
    selection_type, value = select_iso("client")
    if selection_type == "download":
        download_iso("client", value)
    elif selection_type == "custom":
        set_iso_for_build("client", value)
        if RICH_AVAILABLE:
            console.print(f"[green]Using custom Client ISO:[/green] {value.name}")
        else:
            print(f"Using custom Client ISO: {value.name}")

    if RICH_AVAILABLE:
        console.print("\n[green]ISO setup complete![/green]")
    else:
        print("\nISO setup complete!")

    input("\nPress Enter to continue...")

def find_iso(iso_type: str, interactive: bool = False) -> Optional[Path]:
    """Find an ISO file for the given type.

    Args:
        iso_type: "server" or "client"
        interactive: If True and multiple ISOs found, prompt user to choose
    """
    existing = get_existing_isos()
    all_isos = get_all_isos()

    # First check for ISOs matching the type
    if existing[iso_type]:
        if len(existing[iso_type]) == 1 or not interactive:
            return existing[iso_type][0]
        else:
            # Multiple matching ISOs - let user choose
            if RICH_AVAILABLE:
                console.print(f"\n[cyan]Multiple {iso_type} ISOs found. Select one:[/cyan]")
                for i, iso in enumerate(existing[iso_type], 1):
                    size = iso.stat().st_size / (1024**3)
                    console.print(f"  [{i}] {iso.name} ({size:.2f} GB)")
                choice = Prompt.ask("Select", default="1")
            else:
                print(f"\nMultiple {iso_type} ISOs found. Select one:")
                for i, iso in enumerate(existing[iso_type], 1):
                    size = iso.stat().st_size / (1024**3)
                    print(f"  [{i}] {iso.name} ({size:.2f} GB)")
                choice = input("Select [1]: ").strip() or "1"

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(existing[iso_type]):
                    return existing[iso_type][idx]
            except ValueError:
                pass
            return existing[iso_type][0]

    # If no matching type but we have unknown ISOs, offer those
    if all_isos and interactive:
        if RICH_AVAILABLE:
            console.print(f"\n[yellow]No {iso_type} ISO auto-detected.[/yellow]")
            console.print(f"[cyan]Select an ISO to use as {iso_type}:[/cyan]")
            for i, iso in enumerate(all_isos, 1):
                size = iso.stat().st_size / (1024**3)
                console.print(f"  [{i}] {iso.name} ({size:.2f} GB)")
            console.print(f"  [0] Skip")
            choice = Prompt.ask("Select", default="0")
        else:
            print(f"\nNo {iso_type} ISO auto-detected.")
            print(f"Select an ISO to use as {iso_type}:")
            for i, iso in enumerate(all_isos, 1):
                size = iso.stat().st_size / (1024**3)
                print(f"  [{i}] {iso.name} ({size:.2f} GB)")
            print(f"  [0] Skip")
            choice = input("Select [0]: ").strip() or "0"

        try:
            idx = int(choice)
            if idx == 0:
                return None
            if 1 <= idx <= len(all_isos):
                return all_isos[idx - 1]
        except ValueError:
            pass

    return None

def menu_build_boxes():
    """Build Vagrant boxes using Packer."""
    clear_screen()
    print_banner()

    if RICH_AVAILABLE:
        console.print("\n[bold magenta]=== Build Vagrant Boxes (Packer) ===[/bold magenta]\n")
    else:
        print("\n=== Build Vagrant Boxes (Packer) ===\n")

    # Run pre-flight checks (Packer, plugins, VMware networking)
    if not preflight_checks():
        if RICH_AVAILABLE:
            console.print("[red]Pre-flight checks failed. Please fix the issues above.[/red]")
        else:
            print("Pre-flight checks failed. Please fix the issues above.")
        input("\nPress Enter to continue...")
        return

    # Display available ISOs
    display_iso_status()

    # Interactive ISO selection
    if RICH_AVAILABLE:
        console.print("\n[bold]Select ISOs for building:[/bold]")
    else:
        print("\nSelect ISOs for building:")

    server_iso = find_iso("server", interactive=True)
    client_iso = find_iso("client", interactive=True)

    if not server_iso or not client_iso:
        if RICH_AVAILABLE:
            console.print("\n[yellow]Missing ISOs! Please add ISOs to the /iso folder first.[/yellow]")
            console.print(f"[dim]ISO folder: {ISO_DIR}[/dim]")
        else:
            print("\nMissing ISOs! Please add ISOs to the /iso folder first.")
            print(f"ISO folder: {ISO_DIR}")
        input("\nPress Enter to continue...")
        return

    if RICH_AVAILABLE:
        console.print(f"\n[cyan]Server ISO:[/cyan] {server_iso.name}")
        console.print(f"[cyan]Client ISO:[/cyan] {client_iso.name}")
        console.print("\n[yellow]Building Vagrant boxes... This will take 30-60 minutes per box.[/yellow]")

        if not Confirm.ask("Proceed with build?", default=True):
            return
    else:
        print(f"\nServer ISO: {server_iso.name}")
        print(f"Client ISO: {client_iso.name}")
        print("\nBuilding Vagrant boxes... This will take 30-60 minutes per box.")
        if input("Proceed? [Y/n]: ").lower() == 'n':
            return

    os.chdir(PACKER_DIR)
    env = os.environ.copy()
    env["OUTPUT_DIR"] = str(BOXES_DIR)

    # Build Server box (skip if exists)
    server_box = BOXES_DIR / "windows-server-2022.box"
    if server_box.exists():
        if RICH_AVAILABLE:
            console.print(f"\n[green]✓ Server box already exists:[/green] {server_box.name}")
            if not Confirm.ask("Rebuild server box?", default=False):
                pass  # Skip
            else:
                server_box.unlink()  # Delete and rebuild
        else:
            print(f"\n✓ Server box already exists: {server_box.name}")
            if input("Rebuild? [y/N]: ").lower() != 'y':
                pass  # Skip

    if not server_box.exists():
        if RICH_AVAILABLE:
            console.print("\n[bold]Building Windows Server box...[/bold]")
        else:
            print("\nBuilding Windows Server box...")

        env["ISO_PATH"] = str(server_iso)

        result = subprocess.run(
            ["packer", "build", "-force", "-var", f"iso_path={server_iso}", "windows-server-2022.pkr.hcl"],
            env=env
        )

        if result.returncode != 0:
            if RICH_AVAILABLE:
                console.print("[red]Server box build failed![/red]")
            else:
                print("Server box build failed!")
        else:
            if RICH_AVAILABLE:
                console.print("[green]Server box built successfully![/green]")
            else:
                print("Server box built successfully!")

    # Build Client box (skip if exists)
    client_box = BOXES_DIR / "windows-11.box"
    if client_box.exists():
        if RICH_AVAILABLE:
            console.print(f"\n[green]✓ Client box already exists:[/green] {client_box.name}")
            if not Confirm.ask("Rebuild client box?", default=False):
                pass  # Skip
            else:
                client_box.unlink()  # Delete and rebuild
        else:
            print(f"\n✓ Client box already exists: {client_box.name}")
            if input("Rebuild? [y/N]: ").lower() != 'y':
                pass  # Skip

    if not client_box.exists():
        if RICH_AVAILABLE:
            console.print("\n[bold]Building Windows 11 box...[/bold]")
        else:
            print("\nBuilding Windows 11 box...")

        env["ISO_PATH"] = str(client_iso)

        result = subprocess.run(
            ["packer", "build", "-force", "-var", f"iso_path={client_iso}", "windows-11.pkr.hcl"],
            env=env
        )

        if result.returncode != 0:
            if RICH_AVAILABLE:
                console.print("[red]Client box build failed![/red]")
            else:
                print("Client box build failed!")
        else:
            if RICH_AVAILABLE:
                console.print("[green]Client box built successfully![/green]")
            else:
                print("Client box built successfully!")

    os.chdir(PROJECT_ROOT)
    input("\nPress Enter to continue...")

def menu_start_lab():
    """Start the lab using Vagrant."""
    clear_screen()
    print_banner()

    if RICH_AVAILABLE:
        console.print("\n[bold magenta]=== Start Lab ===[/bold magenta]\n")
    else:
        print("\n=== Start Lab ===\n")

    # Check for Vagrant
    if not shutil.which("vagrant"):
        if RICH_AVAILABLE:
            console.print("[red]Vagrant not found! Please install Vagrant first.[/red]")
        else:
            print("Vagrant not found! Please install Vagrant first.")
        input("\nPress Enter to continue...")
        return

    # Check for Vagrant boxes
    box_files = list(BOXES_DIR.glob("*.box"))
    if len(box_files) < 2:
        if RICH_AVAILABLE:
            console.print("[yellow]Vagrant boxes not found! Please build them first (Option 2).[/yellow]")
        else:
            print("Vagrant boxes not found! Please build them first (Option 2).")
        input("\nPress Enter to continue...")
        return

    os.chdir(VAGRANT_DIR)

    if RICH_AVAILABLE:
        console.print("[cyan]Starting Domain Controller (DC01)...[/cyan]")
        console.print("[dim]This will take several minutes for the first boot.[/dim]\n")
    else:
        print("Starting Domain Controller (DC01)...")
        print("This will take several minutes for the first boot.\n")

    # Start DC first
    result = subprocess.run(["vagrant", "up", "dc01"])

    if result.returncode != 0:
        if RICH_AVAILABLE:
            console.print("[red]Failed to start DC01![/red]")
        else:
            print("Failed to start DC01!")
        os.chdir(PROJECT_ROOT)
        input("\nPress Enter to continue...")
        return

    if RICH_AVAILABLE:
        console.print("\n[green]DC01 is running![/green]")
        console.print("[cyan]Waiting for AD to be ready before starting client...[/cyan]")
    else:
        print("\nDC01 is running!")
        print("Waiting for AD to be ready before starting client...")

    # Give AD time to initialize
    import time
    time.sleep(60)

    if RICH_AVAILABLE:
        console.print("\n[cyan]Starting Windows 11 Client (WS01)...[/cyan]")
    else:
        print("\nStarting Windows 11 Client (WS01)...")

    result = subprocess.run(["vagrant", "up", "ws01"])

    if result.returncode != 0:
        if RICH_AVAILABLE:
            console.print("[red]Failed to start WS01![/red]")
        else:
            print("Failed to start WS01!")
    else:
        if RICH_AVAILABLE:
            console.print("\n[bold green]Lab is running![/bold green]")
            console.print("\n[cyan]Connection Info:[/cyan]")
            console.print("  DC01 (Domain Controller): 192.168.56.10")
            console.print("  WS01 (Windows 11 Client): 192.168.56.11")
            console.print("\n[cyan]Credentials:[/cyan]")
            console.print("  Domain: AKATSUKI")
            console.print("  Users: itachi, pain, kisame, deidara, sasori")
            console.print("  Password: Akatsuki123!")
        else:
            print("\nLab is running!")
            print("\nConnection Info:")
            print("  DC01 (Domain Controller): 192.168.56.10")
            print("  WS01 (Windows 11 Client): 192.168.56.11")
            print("\nCredentials:")
            print("  Domain: AKATSUKI")
            print("  Users: itachi, pain, kisame, deidara, sasori")
            print("  Password: Akatsuki123!")

    os.chdir(PROJECT_ROOT)
    input("\nPress Enter to continue...")

def menu_destroy_lab():
    """Destroy the lab."""
    clear_screen()
    print_banner()

    if RICH_AVAILABLE:
        console.print("\n[bold magenta]=== Destroy Lab ===[/bold magenta]\n")
        console.print("[yellow]This will permanently delete all VMs![/yellow]")

        if not Confirm.ask("Are you sure?", default=False):
            return
    else:
        print("\n=== Destroy Lab ===\n")
        print("This will permanently delete all VMs!")
        if input("Are you sure? [y/N]: ").lower() != 'y':
            return

    os.chdir(VAGRANT_DIR)
    subprocess.run(["vagrant", "destroy", "-f"])
    os.chdir(PROJECT_ROOT)

    if RICH_AVAILABLE:
        console.print("\n[green]Lab destroyed.[/green]")
    else:
        print("\nLab destroyed.")

    input("\nPress Enter to continue...")

def menu_status():
    """Show lab status."""
    clear_screen()
    print_banner()

    if RICH_AVAILABLE:
        console.print("\n[bold magenta]=== Lab Status ===[/bold magenta]\n")
    else:
        print("\n=== Lab Status ===\n")

    # ISO Status
    display_iso_status()

    # Box Status
    if RICH_AVAILABLE:
        console.print("\n[bold]Vagrant Boxes:[/bold]")
    else:
        print("\nVagrant Boxes:")

    box_files = list(BOXES_DIR.glob("*.box"))
    if box_files:
        for box in box_files:
            size = box.stat().st_size / (1024**3)
            if RICH_AVAILABLE:
                console.print(f"  [green]{box.name}[/green] ({size:.2f} GB)")
            else:
                print(f"  {box.name} ({size:.2f} GB)")
    else:
        if RICH_AVAILABLE:
            console.print("  [yellow]No boxes built yet[/yellow]")
        else:
            print("  No boxes built yet")

    # Vagrant Status
    if shutil.which("vagrant"):
        if RICH_AVAILABLE:
            console.print("\n[bold]VM Status:[/bold]")
        else:
            print("\nVM Status:")

        os.chdir(VAGRANT_DIR)
        subprocess.run(["vagrant", "status"], capture_output=False)
        os.chdir(PROJECT_ROOT)

    input("\nPress Enter to continue...")

def main_menu():
    """Main menu loop."""
    while True:
        clear_screen()
        print_banner()

        if RICH_AVAILABLE:
            console.print("\n[bold cyan]=== Main Menu ===[/bold cyan]\n")
            console.print("  [1] Manage ISOs [dim](download or select custom)[/dim]")
            console.print("  [2] Build Vagrant Boxes [dim](Packer)[/dim]")
            console.print("  [3] Start Lab")
            console.print("  [4] Destroy Lab")
            console.print("  [5] Status")
            console.print("  [0] Exit\n")

            choice = Prompt.ask("Select option", default="5")
        else:
            print("\n=== Main Menu ===\n")
            print("  [1] Manage ISOs (download or select custom)")
            print("  [2] Build Vagrant Boxes (Packer)")
            print("  [3] Start Lab")
            print("  [4] Destroy Lab")
            print("  [5] Status")
            print("  [0] Exit\n")

            choice = input("Select option: ").strip()

        if choice == "1":
            menu_download_isos()
        elif choice == "2":
            menu_build_boxes()
        elif choice == "3":
            menu_start_lab()
        elif choice == "4":
            menu_destroy_lab()
        elif choice == "5":
            menu_status()
        elif choice == "0":
            if RICH_AVAILABLE:
                console.print("\n[red]Goodbye![/red]")
            else:
                print("\nGoodbye!")
            sys.exit(0)

def main():
    """Entry point."""
    # Ensure directories exist
    ISO_DIR.mkdir(exist_ok=True)
    BOXES_DIR.mkdir(exist_ok=True)

    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(1)

if __name__ == "__main__":
    main()
