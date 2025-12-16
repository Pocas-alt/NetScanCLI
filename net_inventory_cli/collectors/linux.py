"""Linux inventory collector."""

from typing import List

from ..models import OSInfo, HardwareInfo, IPAddressInfo
from ..ssh_client import SSHClient


def collect_inventory(ssh_client: SSHClient) -> dict:
    """Collect inventory from a Linux host.
    
    Args:
        ssh_client: Connected SSH client
        
    Returns:
        Dictionary with os_info, hardware, gui_apps, and limitations
    """
    limitations = []
    
    # OS detection
    os_info = _collect_os_info(ssh_client, limitations)
    
    # Hardware
    hardware = _collect_hardware(ssh_client, limitations)
    
    # GUI applications
    gui_apps = _collect_gui_apps(ssh_client, limitations)
    
    return {
        "os_info": os_info.model_dump() if os_info else None,
        "hardware": hardware.model_dump() if hardware else None,
        "gui_apps": gui_apps,
        "limitations": limitations
    }


def _collect_os_info(ssh_client: SSHClient, limitations: List[str]) -> OSInfo:
    """Collect OS information.
    
    Args:
        ssh_client: Connected SSH client
        limitations: List to append limitations to
        
    Returns:
        OSInfo object
    """
    os_name = None
    os_version = None
    kernel_version = None
    
    # Try /etc/os-release
    stdout, stderr, rc = ssh_client.execute_command("cat /etc/os-release")
    if rc == 0:
        for line in stdout.split('\n'):
            if line.startswith('NAME='):
                os_name = line.split('=', 1)[1].strip('"')
            elif line.startswith('VERSION_ID='):
                os_version = line.split('=', 1)[1].strip('"')
    else:
        limitations.append("Could not read /etc/os-release")
    
    # Get kernel version
    stdout, stderr, rc = ssh_client.execute_command("uname -r")
    if rc == 0:
        kernel_version = stdout.strip()
    else:
        limitations.append("Could not run uname -r")
    
    return OSInfo(
        os_family="linux",
        os_name=os_name,
        os_version=os_version,
        kernel_version=kernel_version
    )


def _collect_hardware(ssh_client: SSHClient, limitations: List[str]) -> HardwareInfo:
    """Collect hardware information.
    
    Args:
        ssh_client: Connected SSH client
        limitations: List to append limitations to
        
    Returns:
        HardwareInfo object
    """
    cpu_model = None
    total_memory = None
    disk_summary = None
    ip_addresses = []
    
    # CPU model
    stdout, stderr, rc = ssh_client.execute_command("lscpu | grep 'Model name'")
    if rc == 0:
        parts = stdout.split(':', 1)
        if len(parts) == 2:
            cpu_model = parts[1].strip()
    else:
        limitations.append("Could not run lscpu (not installed or no permissions)")
    
    # Total memory
    stdout, stderr, rc = ssh_client.execute_command("grep MemTotal /proc/meminfo")
    if rc == 0:
        mem_line = stdout.strip()
        # Parse memory and add GB equivalent
        # Format: "MemTotal:        5770364 kB"
        try:
            parts = mem_line.split()
            if len(parts) >= 2:
                mem_kb = int(parts[1])
                mem_gb = mem_kb / (1024 * 1024)  # Convert KB to GB
                total_memory = f"{mem_line} ({mem_gb:.2f} GB)"
            else:
                total_memory = mem_line
        except (ValueError, IndexError):
            total_memory = mem_line
    else:
        limitations.append("Could not read /proc/meminfo")
        total_memory = None
    
    # Disk summary
    stdout, stderr, rc = ssh_client.execute_command("df -h --total 2>/dev/null | tail -1")
    if rc == 0:
        disk_summary = stdout.strip()
    else:
        limitations.append("Could not run df -h --total")
    
    # IP addresses with descriptions
    stdout, stderr, rc = ssh_client.execute_command("ip -o addr show")
    if rc == 0:
        for line in stdout.split('\n'):
            if not line.strip() or 'inet' not in line:
                continue
            
            parts = line.split()
            interface = parts[1] if len(parts) > 1 else "unknown"
            
            # Extract IP address with CIDR
            ip_addr = None
            for part in parts:
                if '/' in part and 'inet' in parts:
                    ip_addr = part
                    break
            
            if ip_addr:
                description = _categorize_ip_address(ip_addr, interface)
                ip_addresses.append(IPAddressInfo(address=ip_addr, description=description))
    else:
        limitations.append("Could not run ip addr show")
    
    return HardwareInfo(
        cpu_model=cpu_model,
        total_memory=total_memory,
        disk_summary=disk_summary,
        ip_addresses=ip_addresses
    )


def _categorize_ip_address(ip_with_cidr: str, interface: str) -> str:
    """Categorize IP address based on address and interface.
    
    Args:
        ip_with_cidr: IP address with CIDR notation (e.g., "192.168.1.1/24")
        interface: Network interface name
        
    Returns:
        Description string
    """
    ip_part = ip_with_cidr.split('/')[0]
    
    # IPv6
    if ':' in ip_part:
        if ip_part.startswith('fe80::'):
            return f"IPv6 Link-Local ({interface})"
        elif ip_part.startswith('::1'):
            return "IPv6 Loopback"
        elif ip_part.startswith('fd') or ip_part.startswith('fc'):
            return f"IPv6 Unique Local Address ({interface})"
        else:
            return f"IPv6 Global ({interface})"
    
    # IPv4
    if ip_part.startswith('127.'):
        return "IPv4 Loopback"
    elif ip_part.startswith('169.254.'):
        return f"IPv4 Link-Local/Auto-IP ({interface})"
    elif ip_part.startswith('10.'):
        if interface.startswith('docker') or 'docker' in interface.lower():
            return f"Docker bridge ({interface})"
        elif interface.startswith('br-') or interface.startswith('veth'):
            return f"Docker network ({interface})"
        else:
            return f"Private network ({interface})"
    elif ip_part.startswith('172.16.') or ip_part.startswith('172.17.') or ip_part.startswith('172.18.') or \
         (ip_part.startswith('172.') and 16 <= int(ip_part.split('.')[1]) <= 31):
        if interface.startswith('docker') or 'docker' in interface.lower() or interface.startswith('br-'):
            return f"Docker bridge ({interface})"
        else:
            return f"Private network ({interface})"
    elif ip_part.startswith('192.168.'):
        if interface.startswith('docker') or 'docker' in interface.lower() or interface.startswith('br-'):
            return f"Docker bridge ({interface})"
        else:
            return f"Private network ({interface})"
    elif ip_part.startswith('100.'):
        return f"Carrier-Grade NAT/VPN ({interface})"
    else:
        return f"Public/Other ({interface})"


def _collect_gui_apps(ssh_client: SSHClient, limitations: List[str]) -> List[str]:
    """Collect GUI applications.
    
    Args:
        ssh_client: Connected SSH client
        limitations: List to append limitations to
        
    Returns:
        List of application names
    """
    apps = []
    search_paths = [
        "/usr/share/applications",
        "$HOME/.local/share/applications"
    ]
    
    # Find .desktop files
    for path in search_paths:
        stdout, stderr, rc = ssh_client.execute_command(f"find {path} -name '*.desktop' 2>/dev/null")
        if rc == 0 and stdout.strip():
            for desktop_file in stdout.strip().split('\n'):
                if not desktop_file:
                    continue
                
                # Read file and parse Name=
                content_stdout, _, content_rc = ssh_client.execute_command(f"cat '{desktop_file}' 2>/dev/null")
                if content_rc == 0:
                    name = _parse_desktop_name(content_stdout, desktop_file.split('/')[-1])
                    if name:
                        apps.append(name)
    
    if not apps:
        limitations.append("No .desktop files found or find command failed")
    
    # Flatpak apps
    stdout, stderr, rc = ssh_client.execute_command("flatpak list --app 2>/dev/null")
    if rc == 0 and stdout.strip():
        for line in stdout.strip().split('\n'):
            # Flatpak output: Name\tApplication ID\t...
            parts = line.split('\t')
            if parts and parts[0]:
                apps.append(f"{parts[0]} (Flatpak)")
    
    # De-duplicate
    return list(set(apps))


def _parse_desktop_name(content: str, fallback: str) -> str:
    """Extract Name= from .desktop file.
    
    Args:
        content: .desktop file content
        fallback: Fallback name (filename)
        
    Returns:
        Application name
    """
    # Look for non-localized Name= first
    for line in content.split('\n'):
        if line.startswith('Name='):
            return line.split('=', 1)[1].strip()
    
    # Fallback to filename without extension
    return fallback.replace('.desktop', '')
