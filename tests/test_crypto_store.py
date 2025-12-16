"""Tests for encrypted secret store."""

import os
import tempfile
from pathlib import Path

import pytest

from net_inventory_cli.crypto_store import SecretStore


def test_create_new_store():
    """Test creating a new encrypted store."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "secrets.enc"
        store = SecretStore(store_path)
        
        # Create new store
        assert store.create_new("test_passphrase") is True
        assert store.exists()
        assert store.is_unlocked()


def test_unlock_with_correct_passphrase():
    """Test unlocking store with correct passphrase."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "secrets.enc"
        store = SecretStore(store_path)
        
        # Create and unlock
        store.create_new("test_passphrase")
        
        # Create new instance and unlock
        store2 = SecretStore(store_path)
        assert store2.unlock("test_passphrase") is True
        assert store2.is_unlocked()


def test_unlock_with_wrong_passphrase():
    """Test unlocking store with wrong passphrase fails."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "secrets.enc"
        store = SecretStore(store_path)
        
        # Create
        store.create_new("correct_passphrase")
        
        # Try to unlock with wrong passphrase
        store2 = SecretStore(store_path)
        assert store2.unlock("wrong_passphrase") is False
        assert not store2.is_unlocked()


def test_add_retrieve_password():
    """Test adding and retrieving passwords."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "secrets.enc"
        store = SecretStore(store_path)
        store.create_new("test_passphrase")
        
        # Add password
        store.set_password("192.168.1.10", "admin", "secret123")
        
        # Retrieve
        password = store.get_password("192.168.1.10", "admin")
        assert password == "secret123"
        
        # Retrieve non-existent
        password2 = store.get_password("192.168.1.11", "admin")
        assert password2 is None


def test_update_password():
    """Test updating an existing password."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "secrets.enc"
        store = SecretStore(store_path)
        store.create_new("test_passphrase")
        
        # Add password
        store.set_password("192.168.1.10", "admin", "password1")
        
        # Update
        store.set_password("192.168.1.10", "admin", "password2")
        
        # Retrieve should get updated value
        password = store.get_password("192.168.1.10", "admin")
        assert password == "password2"


def test_remove_password():
    """Test removing a password."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "secrets.enc"
        store = SecretStore(store_path)
        store.create_new("test_passphrase")
        
        # Add passwords
        store.set_password("192.168.1.10", "admin", "password1")
        store.set_password("192.168.1.11", "admin", "password2")
        
        # Remove one
        store.remove_password("192.168.1.10", "admin")
        
        # Should be gone
        assert store.get_password("192.168.1.10", "admin") is None
        # Other should remain
        assert store.get_password("192.168.1.11", "admin") == "password2"


def test_list_entries_no_passwords():
    """Test listing entries returns IP and username only, not passwords."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "secrets.enc"
        store = SecretStore(store_path)
        store.create_new("test_passphrase")
        
        # Add passwords
        store.set_password("192.168.1.10", "admin", "password1")
        store.set_password("192.168.1.11", "root", "password2")
        
        # List entries
        entries = store.list_entries()
        
        assert len(entries) == 2
        assert ("192.168.1.10", "admin") in entries
        assert ("192.168.1.11", "root") in entries
        
        # Verify passwords are not in the list
        for entry in entries:
            assert len(entry) == 2  # Only IP and username
            assert "password" not in str(entry).lower()


def test_file_not_plaintext():
    """Test that secrets.enc is not plaintext."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "secrets.enc"
        store = SecretStore(store_path)
        store.create_new("test_passphrase")
        
        # Add sensitive data
        store.set_password("192.168.1.10", "admin", "very_secret_password")
        
        # Read file as bytes
        with open(store_path, 'rb') as f:
            content = f.read()
        
        # Check magic bytes are present
        assert content.startswith(b"NETINV1\x00")
        
        # Check password is not in plaintext
        assert b"very_secret_password" not in content
        assert b"admin" not in content  # Should be encrypted


def test_persistence_across_instances():
    """Test that passwords persist across store instances."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "secrets.enc"
        
        # Create store, add password, close
        store1 = SecretStore(store_path)
        store1.create_new("test_passphrase")
        store1.set_password("192.168.1.10", "admin", "password123")
        
        # Create new instance and unlock
        store2 = SecretStore(store_path)
        assert store2.unlock("test_passphrase") is True
        
        # Password should be retrievable
        password = store2.get_password("192.168.1.10", "admin")
        assert password == "password123"
