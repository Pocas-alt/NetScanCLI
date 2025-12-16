"""Encrypted secret store using Fernet (AES-128-CBC + HMAC)."""

import base64
import json
import os
import struct
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .models import SecretEntry, SecretPayload


# File format constants
MAGIC_BYTES = b"NETINV1\x00"
FORMAT_VERSION = 1
DEFAULT_KDF_ITERATIONS = 480_000  # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
SALT_SIZE = 32


class SecretStore:
    """Manages encrypted password storage with project-local file."""
    
    def __init__(self, path: Path):
        """Initialize secret store.
        
        Args:
            path: Path to secrets.enc file
        """
        self.path = Path(path)
        self._fernet: Optional[Fernet] = None
        self._payload: Optional[SecretPayload] = None
    
    def exists(self) -> bool:
        """Check if secret store file exists."""
        return self.path.exists()
    
    def is_unlocked(self) -> bool:
        """Check if store is currently unlock."""
        return self._fernet is not None and self._payload is not None
    
    def create_new(self, passphrase: str) -> bool:
        """Create a new encrypted store with the given passphrase.
        
        Args:
            passphrase: Master passphrase for encryption
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Generate random salt
            salt = os.urandom(SALT_SIZE)
            
            # Derive key from passphrase
            fernet = self._derive_key(passphrase, salt, DEFAULT_KDF_ITERATIONS)
            
            # Create empty payload
            payload = SecretPayload(version=1, entries=[])
            
            # Encrypt and save
            self._write_encrypted_file(salt, DEFAULT_KDF_ITERATIONS, fernet, payload)
            
            # Store in memory
            self._fernet = fernet
            self._payload = payload
            
            # Attempt to set secure permissions
            self._set_secure_permissions()
            
            return True
        except Exception as e:
            print(f"Error creating secret store: {e}")
            return False
    
    def unlock(self, passphrase: str) -> bool:
        """Unlock and decrypt the secret store.
        
        Args:
            passphrase: Master passphrase
            
        Returns:
            True if successful, False if passphrase wrong or file corrupt
        """
        if not self.exists():
            return False
        
        try:
            # Read and parse file header
            with open(self.path, 'rb') as f:
                # Read magic bytes
                magic = f.read(8)
                if magic != MAGIC_BYTES:
                    print(f"Error: Invalid file format (bad magic bytes)")
                    return False
                
                # Read version
                version_bytes = f.read(1)
                version = struct.unpack('B', version_bytes)[0]
                if version != FORMAT_VERSION:
                    print(f"Error: Unsupported file version {version}")
                    return False
                
                # Read KDF iterations
                iterations_bytes = f.read(4)
                iterations = struct.unpack('>I', iterations_bytes)[0]
                
                # Read salt
                salt = f.read(SALT_SIZE)
                if len(salt) != SALT_SIZE:
                    print("Error: Incomplete file (salt truncated)")
                    return False
                
                # Read encrypted payload
                encrypted_payload = f.read()
            
            # Derive key from passphrase
            fernet = self._derive_key(passphrase, salt, iterations)
            
            # Decrypt payload
            try:
                decrypted_json = fernet.decrypt(encrypted_payload)
                payload_dict = json.loads(decrypted_json)
                payload = SecretPayload(**payload_dict)
            except InvalidToken:
                print("Error: Wrong passphrase or corrupted file")
                return False
           
            # Store in memory
            self._fernet = fernet
            self._payload = payload
            
            return True
        except Exception as e:
            print(f"Error unlocking secret store: {e}")
            return False
    
    def get_password(self, ip: str, username: str) -> Optional[str]:
        """Retrieve password for (ip, username) pair.
        
        Args:
            ip: Host IP address
            username: Username
            
        Returns:
            Password if found, None otherwise
        """
        if not self.is_unlocked():
            return None
        
        for entry in self._payload.entries:
            if entry.ip == ip and entry.username == username:
                return entry.password
        
        return None
    
    def set_password(self, ip: str, username: str, password: str):
        """Add or update password for (ip, username) pair.
        
        Args:
            ip: Host IP address
            username: Username
            password: Password to store
        """
        if not self.is_unlocked():
            raise RuntimeError("Secret store not unlocked")
        
        # Remove existing entry if present
        self._payload.entries = [
            e for e in self._payload.entries
            if not (e.ip == ip and e.username == username)
        ]
        
        # Add new entry
        self._payload.entries.append(SecretEntry(ip=ip, username=username, password=password))
        
        # Re-encrypt and save atomically
        self._save()
    
    def remove_password(self, ip: str, username: str):
        """Remove password for (ip, username) pair.
        
        Args:
            ip: Host IP address
            username: Username
        """
        if not self.is_unlocked():
            raise RuntimeError("Secret store not unlocked")
        
        # Filter out the entry
        original_count = len(self._payload.entries)
        self._payload.entries = [
            e for e in self._payload.entries
            if not (e.ip == ip and e.username == username)
        ]
        
        # Re-encrypt and save if something was removed
        if len(self._payload.entries) < original_count:
            self._save()
    
    def list_entries(self) -> List[Tuple[str, str]]:
        """List all stored entries (IP + username only, never passwords).
        
        Returns:
            List of (ip, username) tuples
        """
        if not self.is_unlocked():
            return []
        
        return [(e.ip, e.username) for e in self._payload.entries]
    
    def _derive_key(self, passphrase: str, salt: bytes, iterations: int) -> Fernet:
        """Derive Fernet key from passphrase using PBKDF2-HMAC-SHA256.
        
        Args:
            passphrase: User passphrase
            salt: Random salt
            iterations: KDF iterations
            
        Returns:
            Fernet instance
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(passphrase.encode('utf-8'))
        fernet_key = base64.urlsafe_b64encode(key)
        return Fernet(fernet_key)
    
    def _save(self):
        """Re-encrypt and save the full store atomically."""
        if not self.is_unlocked():
            raise RuntimeError("Secret store not unlocked")
        
        # Read current file to get salt and iterations
        with open(self.path, 'rb') as f:
            f.read(8)  # magic
            f.read(1)  # version
            iterations_bytes = f.read(4)
            iterations = struct.unpack('>I', iterations_bytes)[0]
            salt = f.read(SALT_SIZE)
        
        # Write atomically
        self._write_encrypted_file(salt, iterations, self._fernet, self._payload)
    
    def _write_encrypted_file(self, salt: bytes, iterations: int, fernet: Fernet, payload: SecretPayload):
        """Write encrypted file atomically (temp + rename).
        
        Args:
            salt: Encryption salt
            iterations: KDF iterations
            fernet: Fernet instance for encryption
            payload: Payload to encrypt
        """
        # Serialize payload
        payload_json = payload.model_dump_json()
        encrypted_payload = fernet.encrypt(payload_json.encode('utf-8'))
        
        # Build file content
        file_content = bytearray()
        file_content.extend(MAGIC_BYTES)
        file_content.extend(struct.pack('B', FORMAT_VERSION))
        file_content.extend(struct.pack('>I', iterations))
        file_content.extend(salt)
        file_content.extend(encrypted_payload)
        
        # Write atomically (temp file + rename)
        temp_fd, temp_path = tempfile.mkstemp(dir=self.path.parent, prefix='.secrets_', suffix='.tmp')
        try:
            os.write(temp_fd, bytes(file_content))
            os.close(temp_fd)
            
            # Set permissions before rename
            try:
                os.chmod(temp_path, 0o600)
            except (OSError, NotImplementedError):
                pass  # Will warn in _set_secure_permissions
            
            # Atomic rename
            os.rename(temp_path, self.path)
        except Exception:
            os.close(temp_fd)
            try:
                os.unlink(temp_path)
            except:
                pass
            raise
    
    def _set_secure_permissions(self):
        """Attempt to set chmod 600 and warn if on unsupported filesystem."""
        try:
            os.chmod(self.path, 0o600)
            # Verify it actually worked
            current_mode = os.stat(self.path).st_mode & 0o777
            if current_mode != 0o600:
                print("\nWARNING: File permissions could not be set (filesystem may be exFAT/FAT32).")
                print("Encryption is your primary security control on this filesystem.\n")
        except (OSError, NotImplementedError):
            print("\nWARNING: File permissions not supported on this filesystem (likely exFAT/FAT32).")
            print("Encryption is your primary security control.\n")
