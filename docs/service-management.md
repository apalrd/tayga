# TAYGA Service Management

This document describes how to install, configure, and manage TAYGA as a system service across different operating systems.

## Supported Service Managers

TAYGA supports the following service management systems:

- **systemd** - Modern Linux distributions (Ubuntu, Debian, CentOS, RHEL, Fedora, etc.)
- **OpenRC** - Alpine Linux, Gentoo, and other init systems
- **launchd** - macOS and OS X
- **FreeBSD rc.d** - FreeBSD and other BSD systems
- **SysV init** - Older Linux distributions and embedded systems

## Quick Start

### 1. Build and Install

```bash
# Build TAYGA
make all

# Install TAYGA and auto-detect service files
sudo make install

# Enable and start the service
sudo make enable-service
sudo make start-service
```

### 2. Check Service Status

```bash
# Check if TAYGA is running
make status-service
```

## Platform-Specific Installation

### Linux with systemd

```bash
# Install systemd service files
sudo make install-systemd

# Enable and start service
sudo systemctl enable tayga@default.service
sudo systemctl start tayga@default.service

# Check status
sudo systemctl status tayga@default.service
```

**Configuration**: `/etc/tayga/default.conf`

### Alpine Linux / Gentoo (OpenRC)

```bash
# Install OpenRC service files
sudo make install-openrc

# Enable and start service
sudo rc-update add tayga default
sudo rc-service tayga start

# Check status
sudo rc-service tayga status
```

**Configuration**: `/etc/tayga.conf`

### macOS (launchd)

```bash
# Install launchd service files
sudo make install-launchd

# Enable and start service
sudo launchctl load -w /Library/LaunchDaemons/com.tayga.plist
sudo launchctl start com.tayga

# Check status
launchctl list | grep com.tayga
```

**Configuration**: `/usr/local/etc/tayga.conf`

### FreeBSD (rc.d)

```bash
# Install FreeBSD rc.d service files
sudo make install-rc

# Enable service (add to /etc/rc.conf)
echo 'tayga_enable="YES"' | sudo tee -a /etc/rc.conf

# Start service
sudo service tayga start

# Check status
sudo service tayga status
```

**Configuration**: `/usr/local/etc/tayga.conf`

### Older Linux (SysV init)

```bash
# Install SysV init service files
sudo make install-sysv

# Enable service (Red Hat/CentOS)
sudo chkconfig tayga on

# OR enable service (Debian/Ubuntu)
sudo update-rc.d tayga defaults

# Start service
sudo service tayga start

# Check status
sudo service tayga status
```

**Configuration**: `/etc/tayga.conf`

## Service Management Commands

TAYGA provides platform-agnostic service management through the Makefile:

```bash
# Enable service (auto-detects platform)
sudo make enable-service

# Disable service
sudo make disable-service

# Start service
sudo make start-service

# Stop service
sudo make stop-service

# Restart service
sudo make restart-service

# Check service status
make status-service
```

## Configuration

### Default Configuration Files

Each platform installs a default configuration file:

- **systemd**: `/etc/tayga/default.conf`
- **OpenRC**: `/etc/tayga.conf`
- **launchd**: `/usr/local/etc/tayga.conf`
- **FreeBSD rc.d**: `/usr/local/etc/tayga.conf`
- **SysV init**: `/etc/tayga.conf`

### Customizing Configuration

1. Edit the appropriate configuration file for your platform
2. Restart the service: `sudo make restart-service`

### Multiple Instances (systemd only)

systemd supports multiple TAYGA instances:

```bash
# Create additional configuration
sudo cp /etc/tayga/default.conf /etc/tayga/instance2.conf

# Edit the new configuration
sudo nano /etc/tayga/instance2.conf

# Enable and start the new instance
sudo systemctl enable tayga@instance2.service
sudo systemctl start tayga@instance2.service
```

## Service Files Reference

### systemd Service File (`scripts/tayga@.service`)

- **Security**: Runs with NoNewPrivileges, ProtectSystem, etc.
- **State Directory**: `/var/lib/tayga`
- **Template Service**: Supports multiple instances with `%i` parameter

### OpenRC Service File (`scripts/tayga.initd`)

- **User/Group**: Runs as `nobody:nogroup` by default
- **PID File**: `/run/tayga.pid`
- **Data Directory**: `/var/lib/tayga`
- **TUN Management**: Automatically creates/removes TUN interface

### launchd Service File (`scripts/com.tayga.plist`)

- **User/Group**: Runs as `root:wheel`
- **Log Files**: `/var/log/tayga.log`
- **Working Directory**: `/var/lib/tayga`
- **Keep Alive**: Automatically restarts if crashed

### FreeBSD rc.d Service File (`scripts/tayga.rc`)

- **Configuration**: Uses `/etc/rc.conf` variables
- **User/Group**: Configurable via `tayga_user`/`tayga_group`
- **TUN Management**: Handles TUN interface lifecycle

### SysV init Service File (`scripts/tayga.sysv`)

- **Configuration**: Uses `/etc/sysconfig/tayga` (Red Hat) or `/etc/default/tayga` (Debian)
- **User/Group**: Configurable via `TAYGA_USER`/`TAYGA_GROUP`
- **Lock File**: `/var/lock/subsys/tayga`

## Troubleshooting

### Service Won't Start

1. Check configuration syntax:
   ```bash
   tayga --config /path/to/config.conf --check-config
   ```

2. Check service logs:
   ```bash
   # systemd
   sudo journalctl -u tayga@default.service
   
   # OpenRC
   sudo rc-service tayga status
   
   # launchd
   tail -f /var/log/tayga.log
   
   # FreeBSD
   sudo service tayga status
   
   # SysV
   sudo service tayga status
   ```

3. Check TUN interface:
   ```bash
   ip link show nat64  # Linux
   ifconfig nat64      # FreeBSD/macOS
   ```

### Permission Issues

1. Ensure TAYGA has CAP_NET_ADMIN capability:
   ```bash
   sudo setcap CAP_NET_ADMIN+ep /usr/local/sbin/tayga
   ```

2. Check file permissions:
   ```bash
   ls -la /usr/local/sbin/tayga
   ls -la /etc/tayga/
   ```

### Network Issues

1. Verify TUN interface creation:
   ```bash
   sudo tayga --mktun
   ip link show nat64
   ```

2. Check routing configuration:
   ```bash
   ip route show
   ip -6 route show
   ```

## Advanced Configuration

### Custom Service Scripts

Some service files support custom pre/post scripts:

- **OpenRC**: Create `/etc/conf.d/tayga` and define `tayga_pre()` function
- **FreeBSD**: Create `/usr/local/etc/rc.d/tayga_pre` and `/usr/local/etc/rc.d/tayga_post`

### Environment Variables

Configure service behavior through environment variables:

```bash
# OpenRC
export tayga_user="tayga"
export tayga_group="tayga"
export tayga_datadir="/var/lib/tayga"

# FreeBSD
tayga_user="tayga"
tayga_group="tayga"
tayga_datadir="/var/lib/tayga"
```

### Resource Limits

Configure resource limits in service files:

- **systemd**: Add `LimitNOFILE=`, `LimitNPROC=` in `[Service]` section
- **launchd**: Add `SoftResourceLimits` and `HardResourceLimits` in plist
- **OpenRC**: Use `ulimit` commands in service script

## Security Considerations

1. **Run as non-root**: Configure service to run as dedicated user
2. **File permissions**: Ensure configuration files are not world-readable
3. **Network isolation**: Use firewall rules to restrict access
4. **Logging**: Monitor service logs for suspicious activity
5. **Updates**: Keep TAYGA updated to latest version

## Migration Between Service Managers

To migrate from one service manager to another:

1. Stop current service
2. Uninstall old service files
3. Install new service files: `sudo make install-<platform>`
4. Configure new service
5. Enable and start new service

Example migration from SysV to systemd:

```bash
# Stop old service
sudo service tayga stop
sudo chkconfig tayga off

# Install systemd service
sudo make install-systemd

# Enable and start new service
sudo systemctl enable tayga@default.service
sudo systemctl start tayga@default.service
```
