# Installing Nmap for Network Admin System

Nmap is an optional dependency that provides advanced network scanning capabilities. The Network Admin System will work without Nmap, but installing it will enable:

- **Advanced OS detection**
- **More accurate port scanning**
- **Service version detection**
- **Enhanced security scanning**

## Windows Installation

### Option 1: Download from Official Website
1. Go to https://nmap.org/download.html
2. Download the latest Windows installer
3. Run the installer as Administrator
4. Add Nmap to your system PATH during installation

### Option 2: Using Chocolatey (if installed)
```cmd
choco install nmap
```

### Option 3: Using Scoop (if installed)
```cmd
scoop install nmap
```

## Linux Installation

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nmap
```

### CentOS/RHEL/Fedora
```bash
sudo yum install nmap
# or for newer versions
sudo dnf install nmap
```

### Arch Linux
```bash
sudo pacman -S nmap
```

## macOS Installation

### Using Homebrew
```bash
brew install nmap
```

### Using MacPorts
```bash
sudo port install nmap
```

## Verification

After installation, verify Nmap is working:

```bash
nmap --version
```

You should see output similar to:
```
Nmap version 7.94 ( https://nmap.org )
```

## Running Without Nmap

If you don't install Nmap, the Network Admin System will still work with:

- **Ping-based device discovery**
- **Basic port scanning**
- **TTL-based OS detection**
- **ARP scanning**

The system will automatically detect if Nmap is available and use alternative methods when it's not.

## Troubleshooting

### Nmap not found in PATH
If you get "nmap program was not found in path" error:

1. **Windows**: Restart your command prompt/terminal after installation
2. **Linux/macOS**: Log out and log back in, or restart your terminal
3. **Manual PATH addition**: Add Nmap installation directory to your system PATH

### Permission Issues
- **Windows**: Run as Administrator
- **Linux/macOS**: Use `sudo` for system-wide installation

### Firewall Issues
Some firewalls may block Nmap. Add exceptions for:
- Nmap executable
- Network scanning ports
- Your local network range 