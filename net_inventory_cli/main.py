"""Main entrypoint for network inventory CLI."""

import getpass
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import questionary
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TaskProgressColumn

from . import collectors
from .crypto_store import SecretStore
from typing import List, Optional
from .models import AuthStatus, AuthType, HardwareInfo, InventoryResult, OSInfo
from .ssh_client import SSHClient
from .storage import Storage
from .wizard import run_wizard


console = Console()


def reset_user_data(storage: Storage, secret_store: SecretStore):
    """Reset/cleanup all user data (passwords, hosts, scan results, etc.).
    
    Args:
        storage: Storage instance
        secret_store: SecretStore instance
    """
    console.print("\n[bold yellow]⚠ WARNING: This will delete ALL user data![/bold yellow]")
    console.print("[yellow]This includes:[/yellow]")
    console.print("  • Encrypted passwords and master passphrase (secrets.enc)")
    console.print("  • Host configurations (hosts.json)")
    console.print("  • Discovered devices (devices.json)")
    console.print("  • SSH known hosts (known_hosts)")
    console.print("  • All scan results (runs/ directory)")
    console.print("  • Test artifacts (.pytest_cache, htmlcov/, etc.)")
    
    confirm = questionary.confirm(
        "\nAre you sure you want to delete all user data?",
        default=False
    ).ask()
    
    if not confirm:
        console.print("[dim]Reset cancelled.[/dim]")
        return
    
    # Delete sensitive files using storage paths (absolute/relative to project root)
    deleted = []
    failed = []
    
    # secrets.enc (use storage root to ensure correct path)
    secrets_path = storage.root / "secrets.enc"
    if secrets_path.exists():
        try:
            secrets_path.unlink()
            deleted.append("secrets.enc")
        except Exception as e:
            failed.append(f"secrets.enc: {e}")
    
    # hosts.json
    hosts_path = storage.hosts_file
    if hosts_path.exists():
        try:
            hosts_path.unlink()
            deleted.append("hosts.json")
        except Exception as e:
            failed.append(f"hosts.json: {e}")
    
    # devices.json
    devices_path = storage.devices_file
    if devices_path.exists():
        try:
            devices_path.unlink()
            deleted.append("devices.json")
        except Exception as e:
            failed.append(f"devices.json: {e}")
    
    # known_hosts (use storage root)
    known_hosts_path = storage.root / "known_hosts"
    if known_hosts_path.exists():
        try:
            known_hosts_path.unlink()
            deleted.append("known_hosts")
        except Exception as e:
            failed.append(f"known_hosts: {e}")
    
    # runs/ directory - delete all contents
    runs_dir = storage.runs_dir
    if runs_dir.exists():
        try:
            # Delete all run subdirectories
            for run_subdir in runs_dir.iterdir():
                if run_subdir.is_dir():
                    try:
                        shutil.rmtree(run_subdir)
                    except Exception as e:
                        failed.append(f"runs/{run_subdir.name}: {e}")
            
            # Try to remove the runs directory itself (might fail if not empty, that's ok)
            try:
                runs_dir.rmdir()
                deleted.append("runs/ directory")
            except:
                # Directory not empty or other issue, but subdirs deleted
                deleted.append("runs/ directory (contents)")
        except Exception as e:
            failed.append(f"runs/: {e}")
    
    # Test artifacts
    test_artifacts = [
        ".pytest_cache",
        "htmlcov",
        ".coverage",
        "coverage.xml",
        ".tox",
        "dist",
        "build"
    ]
    
    for artifact_name in test_artifacts:
        artifact_path = storage.root / artifact_name
        if artifact_path.exists():
            try:
                if artifact_path.is_dir():
                    shutil.rmtree(artifact_path)
                else:
                    artifact_path.unlink()
                deleted.append(artifact_name)
            except Exception as e:
                failed.append(f"{artifact_name}: {e}")
    
    # Clean up any .egg-info directories
    for item in storage.root.iterdir():
        if item.is_dir() and item.name.endswith(".egg-info"):
            try:
                shutil.rmtree(item)
                deleted.append(item.name)
            except Exception as e:
                failed.append(f"{item.name}: {e}")
    
    # Clean up __pycache__ directories recursively
    pycache_dirs = list(storage.root.rglob("__pycache__"))
    for pycache_dir in pycache_dirs:
        try:
            shutil.rmtree(pycache_dir)
            deleted.append(f"__pycache__ ({pycache_dir.relative_to(storage.root)})")
        except Exception as e:
            failed.append(f"__pycache__: {e}")
    
    # Report results
    if deleted:
        console.print(f"\n[green]✓ Deleted {len(deleted)} item(s):[/green]")
        for item in deleted:
            console.print(f"  • {item}")
    
    if failed:
        console.print(f"\n[red]✗ Failed to delete {len(failed)} item(s):[/red]")
        for item in failed:
            console.print(f"  • {item}")
    
    if deleted and not failed:
        console.print("\n[green]✓ All user data has been deleted.[/green]")
        console.print("[dim]The tool is now ready for a new user.[/dim]")
    elif deleted:
        console.print("\n[yellow]⚠ Some items were deleted, but some operations failed.[/yellow]")
        console.print("[dim]Please check the errors above and manually delete remaining files if needed.[/dim]")


def run_scan_with_selection(storage: Storage, secret_store: SecretStore, configured_ips: List[str]):
    """Run scan for specifically configured IPs (called from wizard).
    
    Args:
        storage: Storage instance
        secret_store: SecretStore instance
        configured_ips: List of IPs that were just configured
    """
    run_scan(storage, secret_store, selected_ips=configured_ips)


def print_welcome():
    """Print welcome screen."""
    from rich.columns import Columns
    from rich.panel import Panel
    from rich.text import Text
    
    # ASCII art (network/router icon)
    ascii_art = """⠀⠀⣀⣀⣀⣠⣤⣤⣤⠤⡀⠀⠀⠀⠀⠀⠀⠀⠀
⣠⣤⣤⣤⡤⢴⡶⠶⣤⣄⣉⠙⣦⡀⠀⠀⠀⠀⠀
⢨⣭⣭⡅⣼⣿⣿⡇⠈⢻⣮⡑⣦⡙⢦⣄⡀⠀⠀
⣄⢻⣿⣧⠻⠇⠋⠀⠛⠀⢘⣿⢰⣿⣦⡀⢍⣂⠀
⠈⣃⡙⢿⣧⣙⠶⣿⣿⡷⢘⣡⣿⣿⣿⣿⣆⠹⠂
⠀⠈⠳⡀⠉⠻⣿⣶⣶⡾⠿⠿⠿⠿⠛⠋⣉⡴⠀
⠀⠀⠀⠀⠈⠓⠦⠤⠀⠀⠐⠖⠉⠛⠛⠛⠋⠉⠀"""
    
    # Left side: Text content
    welcome_text = Text()
    welcome_text.append("Network Inventory CLI\n", style="bold cyan")
    welcome_text.append("Portable network device discovery and inventory tool\n\n", style="dim")
    welcome_text.append("Features:", style="bold")
    welcome_text.append("\n  • Multi-CIDR network discovery")
    welcome_text.append("\n  • Encrypted credential storage")
    welcome_text.append("\n  • SSH-based inventory collection")
    welcome_text.append("\n  • Cross-platform support (Linux/macOS/Windows)")
    
    # Create columns: text on left, ASCII art on right
    columns_content = Columns([welcome_text, ascii_art], equal=True, expand=True, padding=(0, 2))
    
    # Single panel containing both columns
    console.print(Panel(columns_content, border_style="cyan", padding=(1, 2)))
    console.print()


def main():
    """Main entrypoint for the network inventory CLI."""
    print_welcome()
    
    # Initialize storage (project-relative paths)
    storage = Storage()
    
    # Initialize secret store
    secrets_path = Path("secrets.enc")
    secret_store = SecretStore(secrets_path)
    
    # Check for reset command FIRST (before unlocking)
    if len(sys.argv) > 1 and sys.argv[1] == "reset":
        reset_user_data(storage, secret_store)
        return
    
    # Check if secret store exists
    if secret_store.exists():
        # Unlock existing store
        console.print(f"[dim]Found existing secret store: {secrets_path}[/dim]")
        
        max_attempts = 3
        for attempt in range(max_attempts):
            passphrase = getpass.getpass("Enter master passphrase to unlock: ")
            
            if secret_store.unlock(passphrase):
                console.print("[green]✓ Secret store unlocked[/green]\n")
                break
            else:
                remaining = max_attempts - attempt - 1
                if remaining > 0:
                    console.print(f"[red]Wrong passphrase. {remaining} attempts remaining.[/red]")
                else:
                    console.print("[red]Failed to unlock secret store. Exiting.[/red]")
                    sys.exit(1)
    else:
        # Create new secret store
        console.print("[yellow]No secret store found.[/yellow]")
        create = questionary.confirm(
            "Create a new encrypted secret store?",
            default=True
        ).ask()
        
        if not create:
            console.print("[yellow]Cannot proceed without secret store. Exiting.[/yellow]")
            sys.exit(1)
        
        console.print("\n[bold]Creating new secret store[/bold]")
        console.print("[yellow]WARNING: If you lose the master passphrase, all stored passwords are UNRECOVERABLE.[/yellow]")
        console.print("[dim]Choose a strong passphrase and store it safely.[/dim]\n")
        
        passphrase = getpass.getpass("Enter master passphrase: ")
        confirm = getpass.getpass("Confirm master passphrase: ")
        
        if passphrase != confirm:
            console.print("[red]Passphrases don't match. Exiting.[/red]")
            sys.exit(1)
        
        if len(passphrase) < 8:
            console.print("[red]Passphrase must be at least 8 characters. Exiting.[/red]")
            sys.exit(1)
        
        if secret_store.create_new(passphrase):
            console.print("[green]✓ Secret store created successfully[/green]\n")
        else:
            console.print("[red]Failed to create secret store. Exiting.[/red]")
            sys.exit(1)
    
    # Check for command-line action
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        # Run scan directly (with optional host selection)
        run_scan(storage, secret_store)
    else:
        # Enter interactive wizard
        run_wizard(storage, secret_store)


def run_scan(storage: Storage, secret_store: SecretStore, selected_ips: Optional[List[str]] = None):
    """Run inventory scan on configured hosts.
    
    Args:
        storage: Storage instance
        secret_store: SecretStore instance
        selected_ips: Optional list of IPs to scan (if None, scans all configured hosts)
    """
    console.print("\n[bold]Starting Inventory Scan[/bold]\n")
    
    # Load hosts with auth_ok status (do not rely on stored ssh_available)
    hosts_file = storage.load_hosts()
    all_hosts = [h for h in hosts_file.hosts if h.last_auth_status == AuthStatus.AUTH_OK]
    
    if not all_hosts:
        console.print("[yellow]No hosts configured with successful authentication.[/yellow]")
        console.print("[dim]Run the wizard to configure hosts first.[/dim]")
        return
    
    # If specific IPs selected, filter hosts
    if selected_ips:
        hosts = [h for h in all_hosts if h.ip in selected_ips]
        if not hosts:
            console.print(f"[yellow]None of the selected IPs ({', '.join(selected_ips)}) are configured with successful authentication.[/yellow]")
            return
    else:
        # Allow user to select which hosts to scan
        choices = []
        for host in all_hosts:
            label = f"{host.ip:15} ({host.username or 'default'})"
            choices.append(questionary.Choice(title=label, value=host.ip))
        
        selected = questionary.checkbox(
            "Select hosts to scan (leave empty to scan all):",
            choices=choices
        ).ask()
        
        if selected:
            hosts = [h for h in all_hosts if h.ip in selected]
        else:
            hosts = all_hosts
    
    console.print(f"Scanning {len(hosts)} host(s)")
    
    # Create run directory
    run_dir = storage.create_run_directory()
    console.print(f"Output directory: {run_dir}\n")
    
    # Scan each host
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TaskProgressColumn(),
    ) as progress:
        task = progress.add_task("Scanning hosts...", total=len(hosts))
        
        # Use thread pool for concurrent scanning (max 5)
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(scan_host, h, secret_store, storage, run_dir): h for h in hosts}
            
            for future in as_completed(futures):
                host = futures[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    console.print(f"[red]Error scanning {host.ip}: {e}[/red]")
                finally:
                    progress.advance(task)
    
    # Save inventory
    if results:
        storage.save_inventory(run_dir, results)
        console.print(f"\n[green]✓ Scan complete![/green]")
        console.print(f"Results saved to: {run_dir}/inventory.json")
        console.print(f"Scanned {len(results)} hosts successfully")
    else:
        console.print("\n[yellow]No results to save[/yellow]")


def scan_host(host, secret_store: SecretStore, storage: Storage, run_dir: Path) -> InventoryResult:
    """Scan a single host and collect inventory.
    
    Args:
        host: HostConfig object
        secret_store: SecretStore instance
        storage: Storage instance
        run_dir: Run directory path
        
    Returns:
        InventoryResult or None if failed
    """
    limitations = []
    timestamp = datetime.now()
    
    # Connect via SSH (will check port 22 availability at runtime)
    client = SSHClient(host.ip, host.username or "admin")
    
    try:
        # Authenticate
        if host.auth.type == AuthType.PASSWORD:
            password = secret_store.get_password(host.ip, host.username or "admin")
            if not password:
                limitations.append("No password found in encrypted store")
                return InventoryResult(
                    ip=host.ip,
                    timestamp=timestamp,
                    limitations=limitations
                )
            
            success, error = client.connect_with_password(password)
        else:
            # SSH key
            success, error = client.connect_with_key(host.auth.key_path)
        
        if not success:
            if "port 22" in error.lower() or "not accessible" in error.lower():
                limitations.append("SSH port 22 not accessible (not scannable)")
                storage.update_host_status(host.ip, AuthStatus.NOT_SCANNABLE)
            else:
                limitations.append(f"SSH connection failed: {error}")
                storage.update_host_status(host.ip, AuthStatus.AUTH_FAILED)
            
            return InventoryResult(
                ip=host.ip,
                timestamp=timestamp,
                limitations=limitations
            )
        
        # Detect OS
        os_type = client.detect_os()
        console.print(f"[dim]{host.ip}: Detected OS={os_type}[/dim]")
        
        # Run appropriate collector
        if os_type == "linux":
            data = collectors.linux.collect_inventory(client)
        elif os_type == "macos":
            data = collectors.macos.collect_inventory(client)
        elif os_type == "windows":
            data = collectors.windows.collect_inventory(client)
        else:
            limitations.append("Unknown OS, could not collect inventory")
            data = {"os_info": None, "hardware": None, "gui_apps": [], "limitations": []}
        
        # Merge limitations from collector
        if "limitations" in data:
            limitations.extend(data["limitations"])
        
        # Build result
        result = InventoryResult(
            ip=host.ip,
            timestamp=timestamp,
            os_info=OSInfo(**data["os_info"]) if data.get("os_info") else None,
            hardware=HardwareInfo(**data["hardware"]) if data.get("hardware") else None,
            gui_apps=data.get("gui_apps", []),
            limitations=limitations
        )
        
        return result
    
    except Exception as e:
        limitations.append(f"Unexpected error: {e}")
        return InventoryResult(
            ip=host.ip,
            timestamp=timestamp,
            limitations=limitations
        )
    finally:
        # Always disconnect, even if an error occurred
        client.disconnect()


if __name__ == "__main__":
    main()
