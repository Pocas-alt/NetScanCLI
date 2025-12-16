"""Network discovery with multi-CIDR support and TCP-only fallback."""

import concurrent.futures
import ipaddress
import platform
import socket
import subprocess
from typing import List, Optional, Set, Tuple

import questionary
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .models import DeviceInfo, DeviceType


# Target ports for discovery and classification
PROBE_PORTS = [22, 3389, 445, 5985]

# Known PC/server vendors (for heuristic classification)
PC_VENDORS = {
    "dell", "hp", "lenovo", "apple", "asus", "acer", "microsoft",
    "intel", "cisco", "vmware", "proxmox", "supermicro"
}

# Hostname keywords suggesting PC/server
PC_KEYWORDS = {
    "server", "desktop", "pc", "workstation", "mac", "win", "linux",
    "laptop", "compute", "node", "host", "vm", "kali", "ubuntu", "debian",
    "centos", "fedora", "rhel", "suse", "arch", "gentoo"
}


def discover_networks(cidrs: List[str]) -> List[DeviceInfo]:
    """Discover devices across multiple CIDRs.
    
    Args:
        cidrs: List of CIDR notation strings (e.g., ["192.168.1.0/24"])
        
    Returns:
        List of discovered devices
    """
    # Parse CIDRs and count total IPs
    all_ips = []
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr.strip(), strict=False)
            all_ips.extend([str(ip) for ip in network.hosts()])
        except ValueError as e:
            print(f"Warning: Invalid CIDR '{cidr}': {e}")
            continue
    
    if not all_ips:
        print("No valid IP addresses to scan")
        return []
    
    # Confirm if large scan
    if not confirm_large_scan(len(all_ips)):
        print("Scan cancelled")
        return []
    
    print(f"\nDiscovering {len(all_ips)} IP addresses...")
    
    # Phase 1: Detect alive hosts (ARP table first, then nmap or TCP fallback)
    alive_ips = discover_alive_hosts(all_ips, cidrs)
    
    if not alive_ips:
        print("No responsive hosts found")
        return []
    
    print(f"\nFound {len(alive_ips)} responsive hosts. Gathering details...")
    
    # Phase 2: Probe ports and gather details for alive hosts
    devices = probe_and_classify(alive_ips)
    
    print(f"\n✓ Discovery complete: {len(devices)} devices found")
    
    return devices


def confirm_large_scan(total_ips: int) -> bool:
    """Prompt user if scan is large to avoid accidental /8 scans.
    
    Args:
        total_ips: Total number of IPs to scan
        
    Returns:
        True if user confirms, False otherwise
    """
    if total_ips > 4096:
        return questionary.confirm(
            f"About to scan {total_ips:,} IP addresses. This may take a while. Continue?",
            default=False
        ).ask()
    return True


def discover_alive_hosts(ips: List[str], cidrs: List[str]) -> Set[str]:
    """Discover alive hosts using ARP table, nmap, or TCP fallback.
    
    Args:
        ips: List of IP addresses to check (for fallback methods)
        cidrs: List of CIDR ranges (for filtering ARP results)
        
    Returns:
        Set of responsive IP addresses
    """
    # Try ARP table first (most comprehensive for local network)
    try:
        arp_ips = _read_arp_table(cidrs)
        if arp_ips:
            print(f"Found {len(arp_ips)} devices in ARP table")
            return arp_ips
        else:
            print("ARP table is empty or no matching devices found, trying other methods...")
    except Exception as e:
        print(f"Note: ARP table read failed ({e}), trying other methods...")
    
    # Try nmap as fallback
    if _has_nmap():
        try:
            alive = _nmap_host_discovery(ips)
            if alive:
                return alive
        except Exception as e:
            print(f"Note: nmap failed ({e}), falling back to TCP probes")
    
    # Final fallback: TCP-only probe
    return _tcp_host_discovery(ips)


def _read_arp_table(cidrs: List[str]) -> Set[str]:
    """Read ARP table and filter IPs by CIDR ranges.
    
    Args:
        cidrs: List of CIDR notation strings to filter by
        
    Returns:
        Set of IP addresses found in ARP table that match CIDRs
    """
    # Parse CIDR networks for filtering
    networks = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            continue
    
    if not networks:
        return set()
    
    # Get ARP table based on platform
    system = platform.system().lower()
    
    if system == "darwin":  # macOS
        cmd = ['arp', '-a', '-n']
    elif system == "linux":
        # Try 'ip neigh' first (modern), fallback to 'arp -a'
        try:
            result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, timeout=5, text=True)
            if result.returncode == 0:
                return _parse_ip_neigh_output(result.stdout, networks)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        cmd = ['arp', '-a', '-n']
    elif system == "windows":
        cmd = ['arp', '-a']
    else:
        # Unknown platform, try generic arp -a
        cmd = ['arp', '-a']
    
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
        if result.returncode != 0:
            return set()
        
        return _parse_arp_output(result.stdout, networks)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise Exception(f"ARP command failed: {e}")


def _parse_ip_neigh_output(output: str, networks: List[ipaddress.IPv4Network]) -> Set[str]:
    """Parse 'ip neigh show' output (Linux).
    
    Args:
        output: Output from 'ip neigh show'
        networks: List of networks to filter by
        
    Returns:
        Set of IP addresses in the networks
    """
    ips = set()
    
    for line in output.split('\n'):
        if not line.strip():
            continue
        
        # Format: IP dev INTERFACE lladdr MAC STALE
        parts = line.split()
        if not parts:
            continue
        
        try:
            ip = ipaddress.ip_address(parts[0])
            # Check if IP is in any of the target networks
            if any(ip in network for network in networks):
                ips.add(str(ip))
        except (ValueError, IndexError):
            continue
    
    return ips


def _parse_arp_output(output: str, networks: List[ipaddress.IPv4Network]) -> Set[str]:
    """Parse ARP table output (macOS/Windows/generic).
    
    Args:
        output: Output from 'arp -a' or 'arp -a -n'
        networks: List of networks to filter by
        
    Returns:
        Set of IP addresses in the networks
    """
    ips = set()
    
    for line in output.split('\n'):
        if not line.strip():
            continue
        
        # macOS format: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
        # Windows format: "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic"
        # Linux format: "192.168.1.1              ether   aa:bb:cc:dd:ee:ff   C                     en0"
        
        # Try to extract IP address (look for IP pattern)
        parts = line.split()
        for part in parts:
            # Remove parentheses, brackets, etc.
            cleaned = part.strip('()[]?')
            
            try:
                ip = ipaddress.ip_address(cleaned)
                # Check if IP is in any of the target networks
                if any(ip in network for network in networks):
                    ips.add(str(ip))
                    break  # Found IP in this line, move to next
            except ValueError:
                continue
    
    return ips


def _has_nmap() -> bool:
    """Check if nmap is available."""
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=2)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _nmap_host_discovery(ips: List[str]) -> Set[str]:
    """Use nmap for host discovery (no sudo required).
    
    Args:
        ips: List of IPs to scan
        
    Returns:
        Set of alive hosts
    """
    # For large lists, use CIDR notation if possible, otherwise use target file
    # For simplicity, we'll scan in batches
    alive_hosts = set()
    
    # Batch IPs (nmap can handle quite a few)
    batch_size = 256
    for i in range(0, len(ips), batch_size):
        batch = ips[i:i+batch_size]
        
        try:
            # -sn: ping scan (no port scan)
            # --unprivileged: no raw sockets (works without sudo)
            cmd = ['nmap', '-sn', '--unprivileged'] + batch
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=60,
                text=True
            )
            
            # Parse output for "Host is up" lines
            for line in result.stdout.split('\n'):
                if "Host is up" in line or "Nmap scan report for" in line:
                    # Extract IP
                    parts = line.split()
                    for part in parts:
                        try:
                            ipaddress.ip_address(part.strip('()'))
                            alive_hosts.add(part.strip('()'))
                            break
                        except ValueError:
                            continue
        except subprocess.TimeoutExpired:
            print(f"Warning: nmap timeout for batch {i//batch_size + 1}")
            continue
    
    return alive_hosts


def _tcp_host_discovery(ips: List[str]) -> Set[str]:
    """Fallback TCP-only host discovery by probing common ports.
    
    Args:
        ips: List of IPs to check
        
    Returns:
        Set of IPs with at least one port responding
    """
    alive_hosts = set()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
    ) as progress:
        task = progress.add_task("Probing hosts...", total=len(ips))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(_check_any_port_open, ip): ip for ip in ips}
            
            for future in concurrent.futures.as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        alive_hosts.add(ip)
                except Exception:
                    pass
                finally:
                    progress.advance(task)
    
    return alive_hosts


def _check_any_port_open(ip: str) -> bool:
    """Check if any of the probe ports is open.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if at least one port responds
    """
    for port in PROBE_PORTS:
        if _tcp_connect(ip, port, timeout=2):
            return True
    return False


def probe_and_classify(ips: Set[str]) -> List[DeviceInfo]:
    """Probe ports and classify devices for alive hosts.
    
    Args:
        ips: Set of alive IP addresses
        
    Returns:
        List of DeviceInfo with classification
    """
    devices = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
    ) as progress:
        task = progress.add_task("Classifying devices...", total=len(ips))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(_probe_device, ip): ip for ip in ips}
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    device = future.result()
                    if device:
                        devices.append(device)
                except Exception as e:
                    print(f"Error probing device: {e}")
                finally:
                    progress.advance(task)
    
    return devices


def _probe_device(ip: str) -> Optional[DeviceInfo]:
    """Probe a single device for ports and gather information.
    
    Args:
        ip: IP address to probe
        
    Returns:
        DeviceInfo or None if unreachable
    """
    # Probe all target ports
    open_ports = []
    for port in PROBE_PORTS:
        if _tcp_connect(ip, port, timeout=2):
            open_ports.append(port)
    
    # Reverse DNS lookup
    hostname = _reverse_dns(ip)
    
    # MAC and vendor (best-effort from ARP)
    mac, vendor = _get_mac_vendor(ip)
    
    # Classify device
    ssh_available = 22 in open_ports
    device_type = _classify_device(open_ports, hostname, vendor)
    
    return DeviceInfo(
        ip=ip,
        hostname=hostname,
        mac=mac,
        vendor=vendor,
        open_ports=open_ports,
        ssh_available=ssh_available,
        device_type=device_type
    )


def _tcp_connect(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Test TCP connection to a port.
    
    Args:
        ip: IP address
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        True if port is open
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        return result == 0
    except:
        return False
    finally:
        sock.close()


def _reverse_dns(ip: str) -> Optional[str]:
    """Attempt reverse DNS lookup.
    
    Args:
        ip: IP address
        
    Returns:
        Hostname or None
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None


def _get_mac_vendor(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """Attempt to get MAC address and vendor from ARP cache.
    
    Args:
        ip: IP address
        
    Returns:
        Tuple of (mac, vendor) or (None, None)
    """
    try:
        # Run arp command (platform-specific)
        result = subprocess.run(
            ['arp', '-n', ip],
            capture_output=True,
            timeout=2,
            text=True
        )
        
        # Parse output for MAC address
        for line in result.stdout.split('\n'):
            if ip in line:
                parts = line.split()
                for part in parts:
                    # MAC address pattern (simple heuristic)
                    if ':' in part and len(part) == 17:
                        mac = part
                        # We don't have OUI lookup, so vendor is None for now
                        return mac, None
    except:
        pass
    
    return None, None


def _classify_device(open_ports: List[int], hostname: Optional[str], vendor: Optional[str]) -> DeviceType:
    """Classify device as likely PC/server or other (IoT/phone).
    
    Args:
        open_ports: List of open ports
        hostname: Reverse DNS hostname
        vendor: MAC vendor
        
    Returns:
        DeviceType classification
    """
    # If SSH (port 22) is open, it's almost certainly a PC/server
    if 22 in open_ports:
        return DeviceType.LIKELY_PC_SERVER
    
    # Check if any other server/PC ports are open
    if any(port in open_ports for port in [3389, 445, 5985]):
        return DeviceType.LIKELY_PC_SERVER
    
    # Check hostname keywords
    if hostname:
        hostname_lower = hostname.lower()
        if any(keyword in hostname_lower for keyword in PC_KEYWORDS):
            return DeviceType.LIKELY_PC_SERVER
    
    # Check vendor
    if vendor:
        vendor_lower = vendor.lower()
        if any(v in vendor_lower for v in PC_VENDORS):
            return DeviceType.LIKELY_PC_SERVER
    
    # Default to "other" (likely IoT, phone, printer, etc.)
    return DeviceType.OTHER
