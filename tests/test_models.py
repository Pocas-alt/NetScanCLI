"""Tests for data models."""

import pytest
from datetime import datetime

from net_inventory_cli.models import (
    AuthConfig,
    AuthStatus,
    AuthType,
    DeviceInfo,
    DeviceType,
    HostConfig,
    HostsFile,
    InventoryResult,
    OSInfo,
    SecretPayload,
)


def test_device_info_schema():
    """Test DeviceInfo model validation."""
    device = DeviceInfo(
        ip="192.168.1.10",
        hostname="test-server",
        mac="00:11:22:33:44:55",
        vendor="Dell Inc.",
        open_ports=[22, 80, 443],
        ssh_available=True,
        device_type=DeviceType.LIKELY_PC_SERVER
    )
    
    assert device.ip == "192.168.1.10"
    assert device.ssh_available is True
    assert device.device_type == DeviceType.LIKELY_PC_SERVER
    assert 22 in device.open_ports


def test_host_config_no_ssh_available():
    """Test that HostConfig does not contain ssh_available field."""
    # HostConfig should only have config, not derived facts
    host = HostConfig(
        ip="192.168.1.10",
        label="server-1",
        username="admin",
        auth=AuthConfig(type=AuthType.PASSWORD),
        last_auth_status=AuthStatus.NOT_CONFIGURED
    )
    
    # Should not have ssh_available attribute
    assert not hasattr(host, 'ssh_available')
    assert host.ip == "192.168.1.10"
    assert host.last_auth_status == AuthStatus.NOT_CONFIGURED


def test_hosts_file_serialization():
    """Test HostsFile JSON serialization."""
    hosts_file = HostsFile()
    hosts_file.hosts.append(
        HostConfig(
            ip="192.168.1.10",
            username="admin",
            auth=AuthConfig(type=AuthType.PASSWORD),
            last_auth_status=AuthStatus.AUTH_OK
        )
    )
    
    # Serialize to dict
    data = hosts_file.model_dump(mode='json')
    
    assert "defaults" in data
    assert "hosts" in data
    assert len(data["hosts"]) == 1
    assert data["hosts"][0]["ip"] == "192.168.1.10"


def test_secret_payload_schema():
    """Test SecretPayload structure."""
    payload = SecretPayload(version=1)
    
    assert payload.version == 1
    assert len(payload.entries) == 0
    
    # Serialize
    data = payload.model_dump()
    assert data["version"] == 1
    assert data["entries"] == []


def test_inventory_result_limitations_always_present():
    """Test that InventoryResult always has limitations field."""
    result = InventoryResult(
        ip="192.168.1.10",
        timestamp=datetime.now()
    )
    
    # limitations should be present (defaults to empty list)
    assert hasattr(result, 'limitations')
    assert isinstance(result.limitations, list)


def test_inventory_result_full():
    """Test complete InventoryResult."""
    result = InventoryResult(
        ip="192.168.1.10",
        timestamp=datetime.now(),
        os_info=OSInfo(
            os_family="linux",
            os_name="Ubuntu",
            os_version="22.04"
        ),
        gui_apps=["Firefox", "Chrome"],
        limitations=["Could not run lscpu"]
    )
    
    assert result.os_info.os_family == "linux"
    assert len(result.gui_apps) == 2
    assert len(result.limitations) == 1
