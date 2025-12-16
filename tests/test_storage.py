"""Tests for storage layer."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from net_inventory_cli.models import DeviceInfo, DeviceType, HostConfig, HostsFile, InventoryResult, AuthConfig, AuthType, AuthStatus
from net_inventory_cli.storage import Storage


def test_atomic_json_write():
    """Test that JSON writes are atomic."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(tmpdir)
        hosts_file = HostsFile()
        hosts_file.hosts.append(
            HostConfig(
                ip="192.168.1.10",
                username="admin",
                auth=AuthConfig(type=AuthType.PASSWORD),
                last_auth_status=AuthStatus.NOT_CONFIGURED
            )
        )
        
        # Write
        storage.save_hosts(hosts_file)
        
        # Verify file exists and is valid JSON
        assert storage.hosts_file.exists()
        with open(storage.hosts_file) as f:
            data = json.load(f)
        
        assert "hosts" in data
        assert len(data["hosts"]) == 1


def test_load_nonexistent_files():
    """Test loading from nonexistent files returns defaults."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(tmpdir)
        
        # Load hosts (should return empty HostsFile)
        hosts = storage.load_hosts()
        assert isinstance(hosts, HostsFile)
        assert len(hosts.hosts) == 0
        
        # Load devices (should return empty list)
        devices = storage.load_devices()
        assert isinstance(devices, list)
        assert len(devices) == 0


def test_save_and_load_devices():
    """Test saving and loading devices."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(tmpdir)
        
        # Create devices
        devices = [
            DeviceInfo(
                ip="192.168.1.10",
                hostname="server-1",
                ssh_available=True,
                device_type=DeviceType.LIKELY_PC_SERVER
            ),
            DeviceInfo(
                ip="192.168.1.50",
                hostname="phone",
                ssh_available=False,
                device_type=DeviceType.OTHER
            )
        ]
        
        # Save
        storage.save_devices(devices)
        
        # Load
        loaded = storage.load_devices()
        assert len(loaded) == 2
        assert loaded[0].ip == "192.168.1.10"
        assert loaded[1].device_type == DeviceType.OTHER


def test_update_host_status():
    """Test updating host authentication status."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(tmpdir)
        
        # Add host
        host = HostConfig(
            ip="192.168.1.10",
            username="admin",
            auth=AuthConfig(type=AuthType.PASSWORD),
            last_auth_status=AuthStatus.NOT_CONFIGURED
        )
        storage.add_or_update_host(host)
        
        # Update status
        storage.update_host_status("192.168.1.10", AuthStatus.AUTH_OK)
        
        # Load and verify
        hosts_file = storage.load_hosts()
        updated_host = next(h for h in hosts_file.hosts if h.ip == "192.168.1.10")
        assert updated_host.last_auth_status == AuthStatus.AUTH_OK


def test_create_run_directory():
    """Test run directory creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(tmpdir)
        
        # Create run directory
        run_dir = storage.create_run_directory()
        
        assert run_dir.exists()
        assert run_dir.is_dir()
        assert run_dir.parent == storage.runs_dir


def test_save_evidence_size_cap():
    """Test evidence output is capped at 200KB."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(tmpdir)
        run_dir = storage.create_run_directory()
        
        # Create large output (>200KB)
        large_output = "X" * (300 * 1024)  # 300KB
        
        # Save evidence
        storage.save_evidence(run_dir, "192.168.1.10", "test_command", large_output)
        
        # Read back
        evidence_file = run_dir / "evidence" / "192.168.1.10" / "test_command.txt"
        assert evidence_file.exists()
        
        with open(evidence_file) as f:
            content = f.read()
        
        # Should be truncated
        assert len(content) < 300 * 1024
        assert "[... OUTPUT TRUNCATED" in content


def test_save_inventory():
    """Test saving inventory results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Storage(tmpdir)
        run_dir = storage.create_run_directory()
        
        # Create results
        results = [
            InventoryResult(
                ip="192.168.1.10",
                timestamp=datetime.now(),
                limitations=["test limitation"]
            )
        ]
        
        # Save
        storage.save_inventory(run_dir, results)
        
        # Verify file
        inventory_file = run_dir / "inventory.json"
        assert inventory_file.exists()
        
        with open(inventory_file) as f:
            data = json.load(f)
        
        assert len(data) == 1
        assert data[0]["ip"] == "192.168.1.10"
