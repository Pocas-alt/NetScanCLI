"""Data models for network inventory CLI."""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field, IPvAnyAddress


class AuthType(str, Enum):
    """Authentication method types."""
    PASSWORD = "password"
    SSH_KEY = "ssh_key"


class DeviceType(str, Enum):
    """Device classification types."""
    LIKELY_PC_SERVER = "likely_pc_server"
    OTHER = "other"


class AuthStatus(str, Enum):
    """Host authentication status."""
    NOT_CONFIGURED = "not_configured"
    AUTH_OK = "auth_ok"
    AUTH_FAILED = "auth_failed"
    NOT_SCANNABLE = "not_scannable"


class AuthConfig(BaseModel):
    """Authentication configuration for a host."""
    type: AuthType
    key_path: Optional[str] = None


class Defaults(BaseModel):
    """Global default settings."""
    username: str = "admin"
    connect_timeout_sec: int = 8


class DeviceInfo(BaseModel):
    """Discovered device information (facts only, no config)."""
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: List[int] = Field(default_factory=list)
    ssh_available: bool = False  # Derived from port 22 being open
    device_type: DeviceType = DeviceType.OTHER


class HostConfig(BaseModel):
    """Host configuration (user-managed, no derived facts like ssh_available)."""
    ip: str
    label: Optional[str] = None
    username: Optional[str] = None  # If None, use defaults
    auth: AuthConfig
    last_auth_status: AuthStatus = AuthStatus.NOT_CONFIGURED


class HostsFile(BaseModel):
    """Structure of hosts.json file."""
    defaults: Defaults = Field(default_factory=Defaults)
    hosts: List[HostConfig] = Field(default_factory=list)


class SecretEntry(BaseModel):
    """Single password entry in encrypted store."""
    ip: str
    username: str
    password: str


class SecretPayload(BaseModel):
    """Decrypted payload structure for secrets.enc."""
    version: int = 1
    entries: List[SecretEntry] = Field(default_factory=list)


class OSInfo(BaseModel):
    """Operating system information."""
    os_family: str  # linux, macos, windows, unknown
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    kernel_version: Optional[str] = None


class IPAddressInfo(BaseModel):
    """IP address with description."""
    address: str  # IP address with CIDR notation
    description: str  # e.g., "Loopback", "Docker bridge", "VPN tunnel", "Physical interface"


class HardwareInfo(BaseModel):
    """Basic hardware summary."""
    cpu_model: Optional[str] = None
    total_memory: Optional[str] = None
    disk_summary: Optional[str] = None
    ip_addresses: List[IPAddressInfo] = Field(default_factory=list)


class InventoryResult(BaseModel):
    """Inventory scan result for a single host."""
    ip: str
    timestamp: datetime
    os_info: Optional[OSInfo] = None
    hardware: Optional[HardwareInfo] = None
    gui_apps: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)  # Always populated


class InventoryRun(BaseModel):
    """Complete inventory run output."""
    run_id: str  # YYYYMMDD-HHMMSS
    started_at: datetime
    completed_at: Optional[datetime] = None
    results: List[InventoryResult] = Field(default_factory=list)
