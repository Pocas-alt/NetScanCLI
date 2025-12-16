"""SSH client with host key verification and command execution."""

import getpass
import hashlib
import socket
from pathlib import Path
from typing import Optional, Tuple

import paramiko
from paramiko.ssh_exception import (
    AuthenticationException,
    BadHostKeyException,
    SSHException,
)


class SSHClient:
    """Wrapper around paramiko for SSH operations with security controls."""
    
    def __init__(self, ip: str, username: str, timeout: int = 8, known_hosts_path: Optional[Path] = None):
        """Initialize SSH client.
        
        Args:
            ip: Host IP address
            username: SSH username
            timeout: Connection timeout in seconds
            known_hosts_path: Path to known_hosts file (defaults to ./known_hosts)
        """
        self.ip = ip
        self.username = username
        self.timeout = timeout
        self.known_hosts_path = Path(known_hosts_path or "./known_hosts")
        self._client: Optional[paramiko.SSHClient] = None
    
    def connect_with_password(self, password: str) -> Tuple[bool, Optional[str]]:
        """Attempt SSH connection with password authentication.
        
        Args:
            password: SSH password
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            self._client = paramiko.SSHClient()
            self._configure_host_key_policy()
            
            self._client.connect(
                hostname=self.ip,
                username=self.username,
                password=password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return True, None
        except AuthenticationException:
            return False, "Authentication failed (wrong password)"
        except BadHostKeyException as e:
            return False, f"Host key verification failed: {e}"
        except socket.timeout:
            return False, f"Connection timeout ({self.timeout}s)"
        except socket.error as e:
            if "Connection refused" in str(e):
                return False, "SSH port 22 not accessible (not scannable)"
            return False, f"Connection error: {e}"
        except SSHException as e:
            return False, f"SSH error: {e}"
        except Exception as e:
            return False, f"Unexpected error: {e}"
    
    def connect_with_key(self, key_path: str, passphrase: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Attempt SSH connection with SSH key authentication.
        
        Args:
            key_path: Path to private SSH key
            passphrase: Key passphrase (will prompt if needed and not provided)
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        try:
            # Expand ~ in key path
            key_path = Path(key_path).expanduser()
            if not key_path.exists():
                return False, f"SSH key not found: {key_path}"
            
            # Load key with passphrase if provided, or prompt if needed
            pkey = None
            try:
                pkey = paramiko.RSAKey.from_private_key_file(str(key_path), password=passphrase)
            except paramiko.PasswordRequiredException:
                if passphrase is None:
                    # Prompt for passphrase (hidden input, not stored)
                    passphrase = getpass.getpass(f"Enter passphrase for key {key_path.name}: ")
                try:
                    pkey = paramiko.RSAKey.from_private_key_file(str(key_path), password=passphrase)
                except:
                    # Try other key types
                    try:
                        pkey = paramiko.Ed25519Key.from_private_key_file(str(key_path), password=passphrase)
                    except:
                        pkey = paramiko.ECDSAKey.from_private_key_file(str(key_path), password=passphrase)
            except:
                # Try other key types without passphrase
                try:
                    pkey = paramiko.Ed25519Key.from_private_key_file(str(key_path), password=passphrase)
                except:
                    pkey = paramiko.ECDSAKey.from_private_key_file(str(key_path), password=passphrase)
            
            self._client = paramiko.SSHClient()
            self._configure_host_key_policy()
            
            self._client.connect(
                hostname=self.ip,
                username=self.username,
                pkey=pkey,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            return True, None
        except AuthenticationException:
            return False, "Authentication failed (wrong key or passphrase)"
        except BadHostKeyException as e:
            return False, f"Host key verification failed: {e}"
        except socket.timeout:
            return False, f"Connection timeout ({self.timeout}s)"
        except socket.error as e:
            if "Connection refused" in str(e):
                return False, "SSH port 22 not accessible (not scannable)"
            return False, f"Connection error: {e}"
        except SSHException as e:
            return False, f"SSH error: {e}"
        except Exception as e:
            return False, f"Unexpected error: {e}"
    
    def execute_command(self, command: str, max_output_bytes: int = 204800) -> Tuple[str, str, int]:
        """Execute command on remote host.
        
        Args:
            command: Command to execute
            max_output_bytes: Maximum output size (default 200KB)
            
        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if not self._client:
            raise RuntimeError("Not connected")
        
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=self.timeout)
            
            # Read output with size limit
            stdout_data = self._read_limited(stdout, max_output_bytes)
            stderr_data = self._read_limited(stderr, max_output_bytes)
            exit_code = stdout.channel.recv_exit_status()
            
            return stdout_data, stderr_data, exit_code
        except Exception as e:
            return "", f"Command execution error: {e}", -1
    
    def detect_os(self) -> str:
        """Detect operating system type.
        
        Returns:
            OS type: "linux", "macos", "windows", "unknown"
        """
        # Try uname first (Unix-like)
        stdout, _, rc = self.execute_command("uname -s")
        if rc == 0:
            os_name = stdout.strip().lower()
            if "linux" in os_name:
                return "linux"
            elif "darwin" in os_name:
                return "macos"
        
        # Try Windows detection via PowerShell
        stdout, _, rc = self.execute_command('powershell.exe -NoProfile -NonInteractive -Command "echo Windows"')
        if rc == 0 and "windows" in stdout.lower():
            return "windows"
        
        return "unknown"
    
    def disconnect(self):
        """Close SSH connection."""
        if self._client:
            self._client.close()
            self._client = None
    
    def _configure_host_key_policy(self):
        """Configure host key verification policy with prompting."""
        # Load known hosts if file exists
        if self.known_hosts_path.exists():
            self._client.load_host_keys(str(self.known_hosts_path))
        
        # Use custom policy that prompts on unknown host
        self._client.set_missing_host_key_policy(PromptAndSavePolicy(self.known_hosts_path))
    
    def _read_limited(self, channel, max_bytes: int) -> str:
        """Read from channel with size limit and truncation marker.
        
        Args:
            channel: paramiko channel
            max_bytes: Maximum bytes to read
            
        Returns:
            Output string, possibly truncated
        """
        data = []
        total_size = 0
        
        for line in channel:
            line_bytes = line if isinstance(line, bytes) else line.encode('utf-8')
            if total_size + len(line_bytes) > max_bytes:
                # Truncate
                remaining = max_bytes - total_size
                if remaining > 0:
                    data.append(line_bytes[:remaining].decode('utf-8', errors='replace'))
                data.append(f"\n\n[... OUTPUT TRUNCATED at {max_bytes} bytes ...]")
                break
            data.append(line if isinstance(line, str) else line.decode('utf-8', errors='replace'))
            total_size += len(line_bytes)
        
        return ''.join(data)


class PromptAndSavePolicy(paramiko.MissingHostKeyPolicy):
    """Host key policy that prompts user to accept unknown keys."""
    
    def __init__(self, known_hosts_path: Path):
        """Initialize policy.
        
        Args:
            known_hosts_path: Path to known_hosts file
        """
        self.known_hosts_path = known_hosts_path
    
    def missing_host_key(self, client, hostname, key):
        """Handle missing host key by prompting user.
        
        Args:
            client: SSH client
            hostname: Hostname
            key: Host key
        """
        # Calculate SHA256 fingerprint
        key_bytes = key.asbytes()
        sha256_hash = hashlib.sha256(key_bytes).digest()
        fingerprint = hashlib.sha256(key_bytes).hexdigest()
        fingerprint_formatted = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        
        print(f"\n{'='*70}")
        print(f"WARNING: Unknown SSH host key for {hostname}")
        print(f"Key type: {key.get_name()}")
        print(f"SHA256 fingerprint: {fingerprint_formatted}")
        print(f"{'='*70}")
        
        response = input("Accept and save this host key? (yes/no): ").strip().lower()
        
        if response == "yes":
            # Add to client's known hosts in memory
            client._host_keys.add(hostname, key.get_name(), key)
            
            # Save to file
            self.known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.known_hosts_path, 'a') as f:
                hostname_line = f"{hostname} {key.get_name()} {key.get_base64()}\n"
                f.write(hostname_line)
            
            print(f"✓ Host key saved to {self.known_hosts_path}")
        else:
            raise paramiko.SSHException("Host key not accepted by user")
