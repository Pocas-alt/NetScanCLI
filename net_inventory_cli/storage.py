"""Storage layer for JSON configuration and inventory files."""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .models import (
    DeviceInfo,
    HostConfig,
    HostsFile,
    InventoryResult,
    InventoryRun,
)


class Storage:
    """Manages persistent storage of configuration and inventory data."""
    
    def __init__(self, project_root: Optional[Path] = None):
        """Initialize storage manager.
        
        Args:
            project_root: Project root directory (defaults to cwd)
        """
        self.root = Path(project_root) if project_root else Path.cwd()
        self.hosts_file = self.root / "hosts.json"
        self.devices_file = self.root / "devices.json"
        self.runs_dir = self.root / "runs"
    
    # Hosts configuration
    
    def load_hosts(self) -> HostsFile:
        """Load hosts configuration from hosts.json.
        
        Returns:
            HostsFile with defaults and host list
        """
        if not self.hosts_file.exists():
            return HostsFile()
        
        try:
            with open(self.hosts_file, 'r') as f:
                data = json.load(f)
            return HostsFile(**data)
        except Exception as e:
            print(f"Error loading hosts.json: {e}")
            return HostsFile()
    
    def save_hosts(self, hosts_file: HostsFile):
        """Save hosts configuration atomically.
        
        Args:
            hosts_file: HostsFile to save
        """
        self._write_json_atomic(self.hosts_file, hosts_file.model_dump(mode='json'))
    
    def update_host_status(self, ip: str, status: str):
        """Update authentication status for a specific host.
        
        Args:
            ip: Host IP address
            status: New auth status
        """
        hosts_file = self.load_hosts()
        for host in hosts_file.hosts:
            if host.ip == ip:
                host.last_auth_status = status
                break
        self.save_hosts(hosts_file)
    
    def add_or_update_host(self, host: HostConfig):
        """Add new host or update existing one.
        
        Args:
            host: HostConfig to add or update
        """
        hosts_file = self.load_hosts()
        # Remove existing entry for this IP
        hosts_file.hosts = [h for h in hosts_file.hosts if h.ip != host.ip]
        # Add new entry
        hosts_file.hosts.append(host)
        self.save_hosts(hosts_file)
    
    # Devices
    
    def load_devices(self) -> List[DeviceInfo]:
        """Load discovered devices from devices.json.
        
        Returns:
            List of DeviceInfo
        """
        if not self.devices_file.exists():
            return []
        
        try:
            with open(self.devices_file, 'r') as f:
                data = json.load(f)
            return [DeviceInfo(**d) for d in data]
        except Exception as e:
            print(f"Error loading devices.json: {e}")
            return []
    
    def save_devices(self, devices: List[DeviceInfo]):
        """Save discovered devices atomically.
        
        Args:
            devices: List of DeviceInfo to save
        """
        data = [d.model_dump(mode='json') for d in devices]
        self._write_json_atomic(self.devices_file, data)
    
    # Inventory runs
    
    def create_run_directory(self) -> Path:
        """Create a new run directory with timestamp.
        
        Returns:
            Path to the created run directory
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        run_dir = self.runs_dir / timestamp
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir
    
    def save_inventory(self, run_dir: Path, results: List[InventoryResult]):
        """Save inventory results to JSON.
        
        Args:
            run_dir: Run directory path
            results: List of inventory results
        """
        inventory_file = run_dir / "inventory.json"
        data = [r.model_dump(mode='json') for r in results]
        self._write_json_atomic(inventory_file, data)
    
    def save_evidence(self, run_dir: Path, ip: str, command_name: str, output: str):
        """Save command evidence output.
        
        Args:
            run_dir: Run directory path
            ip: Host IP address
            command_name: Name of command (for filename)
            output: Command output
        """
        evidence_dir = run_dir / "evidence" / ip
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Sanitize command name for filename
        safe_name = "".join(c if c.isalnum() or c in ('_', '-') else '_' for c in command_name)
        evidence_file = evidence_dir / f"{safe_name}.txt"
        
        # Truncate if too large (200KB max as specified in implementation plan)
        MAX_SIZE = 200 * 1024
        if len(output) > MAX_SIZE:
            truncated = output[:MAX_SIZE]
            truncated += f"\n\n[... OUTPUT TRUNCATED at {MAX_SIZE} bytes ...]"
            output = truncated
        
        with open(evidence_file, 'w') as f:
            f.write(output)
    
    def _write_json_atomic(self, path: Path, data):
        """Write JSON file atomically using temp file + rename.
        
        Args:
            path: Target file path
            data: Data to serialize (must be JSON-serializable)
        """
        # Ensure parent directory exists
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to temp file
        temp_fd, temp_path = tempfile.mkstemp(
            dir=path.parent,
            prefix=f'.{path.name}_',
            suffix='.tmp'
        )
        try:
            # Write JSON with nice formatting
            json_str = json.dumps(data, indent=2, ensure_ascii=False)
            os.write(temp_fd, json_str.encode('utf-8'))
            os.close(temp_fd)
            
            # Atomic rename
            os.rename(temp_path, path)
        except Exception:
            os.close(temp_fd)
            try:
                os.unlink(temp_path)
            except:
                pass
            raise
