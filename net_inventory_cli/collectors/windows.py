"""Windows inventory collector."""

from typing import List

from ..models import OSInfo, HardwareInfo, IPAddressInfo
from ..ssh_client import SSHClient


def windows_ssh_command(powershell_cmd: str) -> str:
    """Wrap PowerShell command for Windows OpenSSH (which defaults to cmd.exe).
    
    Args:
        powershell_cmd: PowerShell command to execute
        
    Returns:
        Wrapped command string
    """
    # Escape inner double quotes
    escaped = powershell_cmd.replace('"', '`"')
    return f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{escaped}"'


def collect_inventory(ssh_client: SSHClient) -> dict:
    """Collect inventory from a Windows host.
    
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
    
    # Get OS information via PowerShell
    cmd = windows_ssh_command(
        "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List"
    )
    stdout, stderr, rc = ssh_client.execute_command(cmd)
    
    if rc == 0:
        for line in stdout.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'Caption':
                    os_name = value
                elif key == 'Version':
                    os_version = value
                elif key == 'BuildNumber':
                    kernel_version = f"Build {value}"
    else:
        limitations.append("Could not run PowerShell Get-CimInstance for OS info (SSH may be using cmd.exe or permissions issue)")
    
    return OSInfo(
        os_family="windows",
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
    cmd = windows_ssh_command("Get-CimInstance Win32_Processor | Select-Object Name | Format-List")
    stdout, stderr, rc = ssh_client.execute_command(cmd)
    if rc == 0:
        for line in stdout.split('\n'):
            if 'Name' in line and ':' in line:
                cpu_model = line.split(':', 1)[1].strip()
                break
    else:
        limitations.append("Could not get CPU info via PowerShell")
    
    # Total memory
    cmd = windows_ssh_command("Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory | Format-List")
    stdout, stderr, rc = ssh_client.execute_command(cmd)
    if rc == 0:
        for line in stdout.split('\n'):
            if 'TotalPhysicalMemory' in line and ':' in line:
                try:
                    mem_bytes = int(line.split(':', 1)[1].strip())
                    mem_gb = mem_bytes / (1024**3)
                    total_memory = f"{mem_gb:.2f} GB ({mem_bytes} bytes)"
                except ValueError:
                    total_memory = line.split(':', 1)[1].strip()
                break
    else:
        limitations.append("Could not get memory info via PowerShell")
    
    # Disk summary
    cmd = windows_ssh_command("Get-PSDrive C | Select-Object Used,Free | Format-List")
    stdout, stderr, rc = ssh_client.execute_command(cmd)
    if rc == 0:
        disk_summary = stdout.strip()
    else:
        limitations.append("Could not get disk info via PowerShell")
    
    # IP addresses with descriptions
    cmd = windows_ssh_command("Get-NetIPAddress | Select-Object IPAddress,InterfaceAlias,AddressFamily | Format-List")
    stdout, stderr, rc = ssh_client.execute_command(cmd)
    if rc == 0:
        current_ip = None
        current_interface = None
        address_family = None
        
        for line in stdout.split('\n'):
            if 'IPAddress' in line and ':' in line:
                current_ip = line.split(':', 1)[1].strip()
            elif 'InterfaceAlias' in line and ':' in line:
                current_interface = line.split(':', 1)[1].strip()
            elif 'AddressFamily' in line and ':' in line:
                address_family = line.split(':', 1)[1].strip()
            
            # When we have all info, process it
            if current_ip and current_interface and address_family:
                if not current_ip.startswith('127.'):
                    # Windows doesn't show CIDR, assume /32 for single host
                    ip_with_cidr = f"{current_ip}/32"
                    description = _categorize_ip_address(current_ip, current_interface, address_family)
                    ip_addresses.append(IPAddressInfo(address=ip_with_cidr, description=description))
                
                # Reset for next entry
                current_ip = None
                current_interface = None
                address_family = None
    else:
        limitations.append("Could not get IP addresses via PowerShell")
    
    return HardwareInfo(
        cpu_model=cpu_model,
        total_memory=total_memory,
        disk_summary=disk_summary,
        ip_addresses=ip_addresses
    )


def _categorize_ip_address(ip: str, interface: str, address_family: str) -> str:
    """Categorize IP address based on address and interface.
    
    Args:
        ip: IP address
        interface: Network interface name
        address_family: AddressFamily (IPv4 or IPv6)
        
    Returns:
        Description string
    """
    # IPv6
    if address_family == "IPv6" or ':' in ip:
        if ip.startswith('fe80::'):
            return f"IPv6 Link-Local ({interface})"
        elif ip == '::1':
            return "IPv6 Loopback"
        elif ip.startswith('fd') or ip.startswith('fc'):
            return f"IPv6 Unique Local Address ({interface})"
        else:
            return f"IPv6 Global ({interface})"
    
    # IPv4
    if ip.startswith('127.'):
        return "IPv4 Loopback"
    elif ip.startswith('169.254.'):
        return f"IPv4 Link-Local/Auto-IP ({interface})"
    elif ip.startswith('10.'):
        if 'docker' in interface.lower() or 'virtual' in interface.lower():
            return f"Virtual/Docker network ({interface})"
        else:
            return f"Private network ({interface})"
    elif ip.startswith('172.16.') or ip.startswith('172.17.') or ip.startswith('172.18.') or \
         (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31):
        if 'docker' in interface.lower() or 'virtual' in interface.lower():
            return f"Virtual/Docker network ({interface})"
        else:
            return f"Private network ({interface})"
    elif ip.startswith('192.168.'):
        if 'docker' in interface.lower() or 'virtual' in interface.lower():
            return f"Virtual/Docker network ({interface})"
        else:
            return f"Private network ({interface})"
    elif ip.startswith('100.'):
        return f"Carrier-Grade NAT/VPN ({interface})"
    else:
        return f"Public/Other ({interface})"


def _collect_gui_apps(ssh_client: SSHClient, limitations: List[str]) -> List[str]:
    """Collect GUI applications from Start Menu.
    
    Args:
        ssh_client: Connected SSH client
        limitations: List to append limitations to
        
    Returns:
        List of application names
    """
    apps = []
    
    # Common Start Menu paths
    paths = [
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs",
        r"$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    ]
    
    for path in paths:
        cmd = windows_ssh_command(
            f'Get-ChildItem "{path}" -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | Select-Object Name | Format-List'
        )
        stdout, stderr, rc = ssh_client.execute_command(cmd)
        
        if rc == 0 and stdout.strip():
            for line in stdout.split('\n'):
                if 'Name' in line and ':' in line:
                    app_name = line.split(':', 1)[1].strip().replace('.lnk', '')
                    if app_name:
                        apps.append(app_name)
    
    if not apps:
        limitations.append("No Start Menu shortcuts found or PowerShell Get-ChildItem failed")
    
    # De-duplicate
    return list(set(apps))
