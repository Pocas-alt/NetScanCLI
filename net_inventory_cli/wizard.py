"""Interactive TUI wizard for network inventory tool."""

import getpass
from pathlib import Path
from typing import List, Optional

import questionary
from rich.console import Console
from rich.table import Table

from .crypto_store import SecretStore
from .discover import discover_networks
from .models import AuthConfig, AuthStatus, AuthType, DeviceInfo, DeviceType, HostConfig
from .ssh_client import SSHClient
from .storage import Storage


console = Console()


def prompt_existing_file_path(message: str) -> Optional[str]:
    """Prompt user for a path and ensure it points to an existing file."""
    while True:
        path_input = questionary.path(message).ask()
        if not path_input:
            return None

        expanded = Path(path_input).expanduser()
        if expanded.is_file():
            return str(expanded)

        console.print("[red]Path must be an existing file.[/red]")
        retry = questionary.confirm("Try entering a different path?", default=True).ask()
        if not retry:
            return None


def run_wizard(storage: Storage, secret_store: SecretStore):
    """Run the main TUI wizard loop.
    
    Args:
        storage: Storage instance
        secret_store: SecretStore instance
    """
    while True:
        # Main menu
        action = questionary.select(
            "Main Menu:",
            choices=[
                "Scan network for devices",
                "Use devices from file",
                "Manage passwords (encrypted store)",
                "Exit"
            ]
        ).ask()
        
        if action == "Exit":
            console.print("\nGoodbye!", style="green")
            break
        elif action == "Scan network for devices":
            scan_network_workflow(storage, secret_store)
        elif action == "Use devices from file":
            use_devices_workflow(storage, secret_store)
        elif action == "Manage passwords (encrypted store)":
            manage_passwords_workflow(secret_store)


def scan_network_workflow(storage: Storage, secret_store: SecretStore):
    """Workflow for scanning network and configuring hosts.
    
    Args:
        storage: Storage instance
        secret_store: SecretStore instance
    """
    # Prompt for CIDRs
    cidrs_input = questionary.text(
        "Enter CIDRs (comma-separated), e.g., 192.168.1.0/24:",
        validate=lambda text: len(text.strip()) > 0 or "CIDRs required"
    ).ask()
    
    if not cidrs_input:
        return
    
    cidrs = [cidr.strip() for cidr in cidrs_input.split(',')]
    
    # Run discovery
    console.print("\n[bold]Starting network discovery...[/bold]")
    devices = discover_networks(cidrs)
    
    if not devices:
        console.print("[yellow]No devices found.[/yellow]")
        return
    
    # Save devices
    storage.save_devices(devices)
    console.print(f"[green]✓[/green] Saved {len(devices)} devices to devices.json")
    
    # Proceed to IP selection
    ip_selection_workflow(devices, storage, secret_store)


def use_devices_workflow(storage: Storage, secret_store: SecretStore):
    """Workflow for using devices from file.
    
    Args:
        storage: Storage instance
        secret_store: SecretStore instance
    """
    devices = storage.load_devices()
    
    if not devices:
        console.print("[yellow]No devices found in devices.json[/yellow]")
        create_sample = questionary.confirm("Create sample devices.json?", default=False).ask()
        if create_sample:
            # Create sample with current samples
            devices = storage.load_devices()  # Will have sample data
        return
    
    console.print(f"[green]✓[/green] Loaded {len(devices)} devices from devices.json")
    ip_selection_workflow(devices, storage, secret_store)


def ip_selection_workflow(devices: List[DeviceInfo], storage: Storage, secret_store: SecretStore):
    """Workflow for selecting IPs to manage.
    
    Args:
        devices: List of discovered devices
        storage: Storage instance
        secret_store: SecretStore instance
    """
    # Filter option
    show_all = questionary.confirm(
        "Show all devices (including IoT/phones)? Default: only show likely PCs/servers",
        default=False
    ).ask()
    
    if not show_all:
        filtered = [d for d in devices if d.device_type == DeviceType.LIKELY_PC_SERVER]
        console.print(f"[dim]Filtered to {len(filtered)} likely PC/server devices[/dim]")
        devices = filtered
    
    if not devices:
        console.print("[yellow]No devices match filter[/yellow]")
        return
    
    # Load existing host configs for status
    hosts_file = storage.load_hosts()
    host_status_map = {h.ip: h.last_auth_status for h in hosts_file.hosts}
    
    # Build choices with status badges (plain text, no Rich markup for questionary)
    choices = []
    for device in devices:
        status = host_status_map.get(device.ip, AuthStatus.NOT_CONFIGURED)
        ssh_badge = "SSH: yes" if device.ssh_available else "SSH: no"
        
        if status == AuthStatus.AUTH_OK:
            status_badge = "✓ auth ok"
        elif status == AuthStatus.AUTH_FAILED:
            status_badge = "✗ auth failed"
        elif status == AuthStatus.NOT_SCANNABLE:
            status_badge = "⚠ not scannable"
        else:
            status_badge = "○ not configured"
        
        label = f"{device.ip:15} ({device.hostname or 'unknown':20}) [{ssh_badge}] {status_badge}"
        choices.append(questionary.Choice(title=label, value=device.ip))
    
    # Multi-select IPs
    selected_ips = questionary.checkbox(
        "Select devices to manage:",
        choices=choices
    ).ask()
    
    if not selected_ips:
        return
    
    # Proceed to credential mapping
    credential_mapping_workflow(selected_ips, storage, secret_store)


def credential_mapping_workflow(selected_ips: List[str], storage: Storage, secret_store: SecretStore):
    """Workflow for mapping credentials to selected IPs.
    
    Args:
        selected_ips: List of selected IP addresses
        storage: Storage instance
        secret_store: SecretStore instance
    """
    hosts_file = storage.load_hosts()
    defaults = hosts_file.defaults
    
    for ip in selected_ips:
        console.print(f"\n[bold]{'='*70}[/bold]")
        console.print(f"[bold]Configuring {ip}[/bold]")
        console.print(f"[bold]{'='*70}[/bold]")
        
        # Find existing config
        existing = next((h for h in hosts_file.hosts if h.ip == ip), None)
        
        # Username
        default_username = existing.username if existing else defaults.username
        username = questionary.text(
            "Username:",
            default=default_username
        ).ask()
        
        if not username:
            username = default_username
        
        # Auth method
        auth_method = questionary.select(
            "Auth method:",
            choices=[
                "Password (from encrypted store)",
                "SSH Key"
            ]
        ).ask()
        
        auth_config = None
        validation_success = False
        
        if auth_method == "SSH Key":
            # SSH Key path
            key_path = prompt_existing_file_path("SSH key path:")
            
            if not key_path:
                console.print("[yellow]No key path provided, skipping this host[/yellow]")
                continue
            
            auth_config = AuthConfig(type=AuthType.SSH_KEY, key_path=key_path)
            
            # Validate connection
            console.print(f"[dim]Validating SSH connection to {ip}...[/dim]")
            client = SSHClient(ip, username)
            success, error = client.connect_with_key(key_path)
            
            if success:
                console.print("[green]✓ Connection successful[/green]")
                client.disconnect()
                validation_success = True
            else:
                console.print(f"[red]✗ Connection failed: {error}[/red]")
                retry = questionary.confirm("Retry configuration for this host?", default=True).ask()
                if not retry:
                    continue
                else:
                    # Go back to this IP
                    selected_ips.insert(selected_ips.index(ip), ip)
                    continue
        else:
            # Password auth
            auth_config = AuthConfig(type=AuthType.PASSWORD)
            
            # Check if password exists
            password = secret_store.get_password(ip, username)
            if not password:
                console.print(f"[yellow]No password found for {username}@{ip}[/yellow]")
                add_now = questionary.confirm("Add password now?", default=True).ask()
                if add_now:
                    password = getpass.getpass(f"Password for {username}@{ip}: ")
                    confirm_pass = getpass.getpass("Confirm password: ")
                    
                    if password != confirm_pass:
                        console.print("[red]Passwords don't match![/red]")
                        continue
                    
                    secret_store.set_password(ip, username, password)
                    console.print("[green]✓ Password saved (encrypted)[/green]")
                else:
                    console.print("[yellow]Skipping this host[/yellow]")
                    continue
            else:
                console.print(f"[green]✓ Using stored password for {username}@{ip}[/green]")
            
            # Validate connection
            console.print(f"[dim]Validating SSH connection to {ip}...[/dim]")
            password = secret_store.get_password(ip, username)
            client = SSHClient(ip, username)
            success, error = client.connect_with_password(password)
            
            if success:
                console.print("[green]✓ Connection successful[/green]")
                client.disconnect()
                validation_success = True
            else:
                console.print(f"[red]✗ Connection failed: {error}[/red]")
                retry = questionary.confirm("Retry configuration for this host?", default=True).ask()
                if not retry:
                    storage.update_host_status(ip, AuthStatus.AUTH_FAILED)
                    continue
                else:
                    # Go back to this IP
                    selected_ips.insert(selected_ips.index(ip), ip)
                    continue
        
        # Save host config
        if validation_success:
            host_config = HostConfig(
                ip=ip,
                label=None,
                username=username,
                auth=auth_config,
                last_auth_status=AuthStatus.AUTH_OK
            )
            storage.add_or_update_host(host_config)
            console.print(f"[green]✓ Saved configuration for {ip}[/green]")
    
    # Collect successfully configured IPs
    configured_ips = []
    for ip in selected_ips:
        hosts_file = storage.load_hosts()
        host = next((h for h in hosts_file.hosts if h.ip == ip), None)
        if host and host.last_auth_status == AuthStatus.AUTH_OK:
            configured_ips.append(ip)
    
    # After all configured, show action menu
    if configured_ips:
        action_menu_workflow(storage, secret_store, configured_ips)


def action_menu_workflow(storage: Storage, secret_store: SecretStore, configured_ips: List[str]):
    """Action menu after credential mapping.
    
    Args:
        storage: Storage instance
        secret_store: SecretStore instance
        configured_ips: List of IPs that were just configured
    """
    action = questionary.select(
        "\nWhat would you like to do?",
        choices=[
            "Scan configured hosts now",
            "Add/edit another host login",
            "Return to main menu"
        ]
    ).ask()
    
    if action == "Scan configured hosts now":
        # Import here to avoid circular imports
        from .main import run_scan_with_selection
        run_scan_with_selection(storage, secret_store, configured_ips)
    elif action == "Add/edit another host login":
        console.print("[dim]Returning to main menu to add more hosts...[/dim]")


def manage_passwords_workflow(secret_store: SecretStore):
    """Workflow for managing passwords in encrypted store.
    
    Args:
        secret_store: SecretStore instance
    """
    if not secret_store.is_unlocked():
        console.print("[red]Secret store is locked. Cannot manage passwords.[/red]")
        return
    
    while True:
        action = questionary.select(
            "Password Management:",
            choices=[
                "Add/update password for a host",
                "Remove password for a host",
                "List stored entries (IP + username only)",
                "Return to main menu"
            ]
        ).ask()
        
        if action == "Return to main menu":
            break
        elif action == "Add/update password for a host":
            ip = questionary.text("IP address:").ask()
            if not ip:
                continue
            
            username = questionary.text("Username:").ask()
            if not username:
                continue
            
            password = getpass.getpass(f"Password for {username}@{ip}: ")
            confirm = getpass.getpass("Confirm password: ")
            
            if password != confirm:
                console.print("[red]Passwords don't match![/red]")
                continue
            
            secret_store.set_password(ip, username, password)
            console.print("[green]✓ Password saved (encrypted)[/green]")
        
        elif action == "Remove password for a host":
            entries = secret_store.list_entries()
            if not entries:
                console.print("[yellow]No passwords stored[/yellow]")
                continue
            
            choices = [f"{username}@{ip}" for ip, username in entries]
            selected = questionary.select(
                "Select entry to remove:",
                choices=choices
            ).ask()
            
            if selected:
                ip, username = selected.split('@')[1], selected.split('@')[0]
                secret_store.remove_password(ip, username)
                console.print(f"[green]✓ Removed password for {selected}[/green]")
        
        elif action == "List stored entries (IP + username only)":
            entries = secret_store.list_entries()
            if not entries:
                console.print("[yellow]No passwords stored[/yellow]")
            else:
                table = Table(title="Stored Password Entries")
                table.add_column("Username", style="cyan")
                table.add_column("IP Address", style="magenta")
                
                for ip, username in entries:
                    table.add_row(username, ip)
                
                console.print(table)
