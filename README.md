# Network Inventory CLI

A portable, USB-friendly CLI tool for discovering network devices and inventorying SSH-capable hosts with encrypted credential storage and read-only operations.

## Features

- **Multi-CIDR Network Discovery**
  - TCP-based discovery (no sudo required)
  - nmap integration (optional, falls back to pure Python)
  - Device classification (PC/server vs IoT/phones)
  - Large scan confirmation (>4096 IPs)

- **Encrypted Credential Storage**
  - Fernet encryption (AES-128-CBC + HMAC)
  - PBKDF2-HMAC-SHA256 with 480,000 iterations
  - Password-only input via TUI wizard (no plaintext files)
  - Project-local secret store (USB-portable)

- **SSH-Based Inventory Collection**
  - OS detection (Linux, macOS, Windows)
  - Basic hardware summary (CPU, memory, disk, IPs)
  - GUI applications (not full package lists)
  - SSH host key verification with fingerprint prompting
  - Read-only commands only

- **Cross-Platform Support**
  - macOS, Linux collectors with proper path handling
  - Windows collector with PowerShell command wrapping
  - USB-portable (works from exFAT/FAT32 drives)

## Installation

### Requirements

- Python 3.11 or later
- SSH access to target hosts

### Setup

```bash
cd net-inventory-cli
pip install -e .
```

Or with development dependencies (includes pytest and pytest-cov):

```bash
pip install -e ".[dev]"
```

## Testing

**Important:** You must use the virtual environment's Python/pytest, not the system one!

### Setup

1. **Activate the virtual environment**:
   ```bash
   source venv/bin/activate  # macOS/Linux
   # or
   .\venv\Scripts\activate  # Windows
   ```

2. **Install with dev dependencies** (if not already done):
   ```bash
   pip install -e ".[dev]"
   ```

### Running Tests

**Option 1: With venv activated** (recommended):
```bash
# Make sure venv is activated (you should see (venv) in your prompt)
pytest tests/ -v
```

**Option 2: Use venv's pytest directly** (if venv not activated):
```bash
venv/bin/pytest tests/ -v  # macOS/Linux
# or
venv\Scripts\pytest tests/ -v  # Windows
```

**With coverage:**
```bash
# Using venv's pytest
venv/bin/pytest tests/ --cov=net_inventory_cli --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
# or
xdg-open htmlcov/index.html  # Linux
```

**Troubleshooting:** If you get `ModuleNotFoundError: No module named 'cryptography'`:
- You're using system Python instead of venv Python
- Solution: Use `venv/bin/pytest` or activate the venv first with `source venv/bin/activate`
- Verify with: `which pytest` (should show `venv/bin/pytest`, not `/usr/local/bin/pytest`)

## Quick Start

### Interactive Wizard

```bash
python -m net_inventory_cli
```

On first run, you'll be prompted to create an encrypted secret store. Choose a strong master passphrase - **if you lose it, all stored passwords are UNRECOVERABLE**.

### Workflow

1. **Scan Network** or **Use Devices from File**
   - Scan discovers devices across multiple CIDRs
   - Filters to "likely PC/server" by default
   
2. **Select IPs to Manage**
   - Multi-select with status badges (auth ok/failed/not configured)
   
3. **Configure Credentials**
   - Enter username and choose password or SSH key
   - Passwords entered via hidden input (never displayed)
   - SSH connection validated before proceeding
   
4. **Manage Passwords**
   - Add/update/remove passwords
   - List entries (IP + username only, never shows passwords)

5. **Run Scan**
   ```bash
   python -m net_inventory_cli scan
   ```

### Reset All Data

To delete all user data before passing the tool to another user:

```bash
python -m net_inventory_cli reset
```

This will delete:
- Encrypted passwords and master passphrase (`secrets.enc`)
- Host configurations (`hosts.json`)
- Discovered devices (`devices.json`)
- SSH known hosts (`known_hosts`)
- All scan results (`runs/` directory)

## Discovery Limitations

**TCP-Only Discovery**: The tool finds hosts that respond on at least one of: **22, 3389, 445, 5985**. Hosts with all of these ports closed may not be discovered.

**No Sudo Required**: Discovery uses best-effort methods without requiring sudo:
- Prefers nmap if available (with `--unprivileged` flag)
- Falls back to pure Python TCP connect checks
- MAC/vendor information is best-effort from ARP cache

## Security Guidance

### Master Passphrase

- The master passphrase encrypts all stored passwords
- **There is NO recovery mechanism** - if you lose it, all passwords are lost
- Choose a strong, memorable passphrase (min 8 characters)
- Store it securely (password manager recommended)

### Encryption Details

- File format: `NETINV1` magic bytes + version + KDF params + salt + Fernet token
- KDF: PBKDF2-HMAC-SHA256, 480,000 iterations (OWASP 2023 recommendation)
- Encryption: Fernet (AES-128-CBC + HMAC-SHA256)

### SSH Host Key Policy

- Host keys stored in project-local `known_hosts` file
- On first connection: fingerprint (SHA256) displayed, user must accept
- On subsequent connections: verified against stored key
- If key changes: connection refused with MITM warning

### SSH Key Passphrases

- SSH key passphrases are **NOT stored**
- Prompted (hidden input) at connection time only
- Each connection requires re-entering passphrase if key is encrypted

### USB Filesystem Permissions

On exFAT/FAT32 USB drives, file permissions (chmod 600) cannot be enforced. The tool will attempt to set permissions but warn if unsuccessful. **Encryption is your primary security control on these filesystems.**

## File Structure

```
net-inventory-cli/
├── hosts.json              # Plaintext host metadata (NO passwords)
├── devices.json             # Discovered devices list
├── secrets.enc             # Encrypted password store
├── known_hosts             # SSH host keys (project-local)
├── runs/                   # Inventory scan outputs
│   └── YYYYMMDD-HHMMSS/
│       ├── inventory.json  # Structured inventory results
│       └── evidence/       # Raw command outputs (per IP)
└── net_inventory_cli/      # Python package
```

## Portable USB Usage

The tool uses **relative paths** for all configuration and output files, making it fully portable:

1. Copy entire `net-inventory-cli/` directory to USB drive
2. Run from USB path:
   ```bash
   cd /Volumes/USB/net-inventory-cli
   python -m net_inventory_cli
   ```
3. All data (secrets.enc, hosts.json, devices.json, runs/) stays on USB

## Output Schema

### inventory.json

```json
[
  {
    "ip": "192.168.1.10",
    "timestamp": "2025-12-15T23:45:00",
    "os_info": {
      "os_family": "linux",
      "os_name": "Ubuntu",
      "os_version": "22.04",
      "kernel_version": "5.15.0-91-generic"
    },
    "hardware": {
      "cpu_model": "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",
      "total_memory": "MemTotal:       16384000 kB",
      "disk_summary": "total    1.8T  500G  1.2T  30% -",
      "ip_addresses": ["192.168.1.10/24", "10.0.0.5/8"]
    },
    "gui_apps": [
      "Firefox",
      "Visual Studio Code",
      "Slack (Flatpak)"
    ],
    "limitations": [
      "Could not run lscpu (not installed or no permissions)"
    ]
  }
]
```

### Evidence Files

Raw command outputs saved to `runs/<timestamp>/evidence/<ip>/`:
- `os_release.txt`
- `uname.txt`
- `lscpu.txt`
- etc.

Output capped at 200KB per command with truncation markers.

## Troubleshooting

### SSH Connection Failures

- **Port 22 not accessible**: Host may not have SSH enabled or firewall blocking
- **Authentication failed**: Check password in encrypted store or SSH key path
- **Host key changed**: MITM warning - verify host hasn't been compromised before accepting

### Discovery Issues

- **No devices found**: Check CIDR notation and network connectivity
- **nmap not found**: Tool will fall back to TCP probes automatically
- **Scan timeout**: Reduce CIDR size or check network performance

### Permissions

- **`secrets.enc` permission warning**: Normal on exFAT/FAT32 USB drives, encryption still protects data
- **Cannot collect hardware info**: Some commands require specific packages (lscpu, sysctl, etc.)

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Test Coverage

```bash
pytest tests/ --cov=net_inventory_cli --cov-report=html
```

## License

MIT

## Contributing

Issues and pull requests welcome. Please ensure all tests pass before submitting.

## Security Disclosure

Found a security issue? Please email matas@odontologas.lt (do NOT open public issue).


# TL;DR
## First run

```
cd ~/.../NetScanCLI
python3 -m venv venv          # Create virtual environment
source venv/bin/activate      # Activate it
pip install -e .              # Install the tool with dependencies
python -m net_inventory_cli   # Run it
```
## How to close virtual environment
```
deactivate
```
