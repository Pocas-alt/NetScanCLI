"""macOS inventory collector."""

from typing import List

from ..models import OSInfo, HardwareInfo, IPAddressInfo
from ..ssh_client import SSHClient


def collect_inventory(ssh_client: SSHClient) -> dict:
    """Collect inventory from a macOS host.
    
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
    
    # Try sw_vers
    stdout, stderr, rc = ssh_client.execute_command("sw_vers")
    if rc == 0:
        for line in stdout.split('\n'):
            if 'ProductName:' in line:
                os_name = line.split(':', 1)[1].strip()
            elif 'ProductVersion:' in line:
                os_version = line.split(':', 1)[1].strip()
    else:
        limitations.append("Could not run sw_vers")
    
    # Get kernel version
    stdout, stderr, rc = ssh_client.execute_command("uname -r")
    if rc == 0:
        kernel_version = stdout.strip()
    else:
        limitations.append("Could not run uname -r")
    
    return OSInfo(
        os_family="macos",
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
    stdout, stderr, rc = ssh_client.execute_command("sysctl -n machdep.cpu.brand_string")
    if rc == 0:
        cpu_model = stdout.strip()
    else:
        limitations.append("Could not run sysctl for CPU info")
    
    # Total memory
    stdout, stderr, rc = ssh_client.execute_command("sysctl -n hw.memsize")
    if rc == 0:
        try:
            mem_bytes = int(stdout.strip())
            mem_gb = mem_bytes / (1024**3)
            total_memory = f"{mem_gb:.2f} GB ({mem_bytes} bytes)"
        except ValueError:
            total_memory = stdout.strip()
    else:
        limitations.append("Could not run sysctl for memory info")
    
    # Disk summary
    stdout, stderr, rc = ssh_client.execute_command("df -h / | tail -1")
    if rc == 0:
        disk_summary = stdout.strip()
    else:
        limitations.append("Could not run df")
    
    # IP addresses with descriptions
    stdout, stderr, rc = ssh_client.execute_command("ifconfig")
    if rc == 0:
        current_interface = None
        for line in stdout.split('\n'):
            # Detect interface name
            if line and not line.startswith(' ') and not line.startswith('\t') and ':' in line:
                current_interface = line.split(':')[0]
            
            # Extract IP addresses
            if 'inet ' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == 'inet' and i + 1 < len(parts):
                        ip_addr = parts[i + 1]
                        if '/' in ip_addr:
                            ip_part = ip_addr.split('/')[0]
                        else:
                            ip_part = ip_addr
                        
                        if not ip_part.startswith('127.'):
                            description = _categorize_ip_address(ip_addr, current_interface or "unknown")
                            ip_addresses.append(IPAddressInfo(address=ip_addr, description=description))
    else:
        limitations.append("Could not run ifconfig")
    
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
        if 'docker' in interface.lower() or interface.startswith('br-'):
            return f"Docker bridge ({interface})"
        else:
            return f"Private network ({interface})"
    elif ip_part.startswith('172.16.') or ip_part.startswith('172.17.') or ip_part.startswith('172.18.') or \
         (ip_part.startswith('172.') and 16 <= int(ip_part.split('.')[1]) <= 31):
        if 'docker' in interface.lower() or interface.startswith('br-'):
            return f"Docker bridge ({interface})"
        else:
            return f"Private network ({interface})"
    elif ip_part.startswith('192.168.'):
        if 'docker' in interface.lower() or interface.startswith('br-'):
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
    base_paths = ["/Applications", "$HOME/Applications"]
    
    for base_path in base_paths:
        stdout, stderr, rc = ssh_client.execute_command(
            f"find {base_path} -maxdepth 2 -name '*.app' -type d 2>/dev/null"
        )
        
        if rc == 0 and stdout.strip():
            for app_path in stdout.strip().split('\n'):
                if app_path:
                    # Extract app name from path, handle spaces safely
                    app_name = app_path.split('/')[-1].replace('.app', '')
                    apps.append(app_name)
    
    if not apps:
        limitations.append("No .app bundles found or find command failed")
    
    # De-duplicate
    return list(set(apps))
