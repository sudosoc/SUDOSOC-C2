This script installs the latest version of Sliver as a systemd service, installs Windows cross-compiler dependencies (mingw), and sets up multiplayer for all local users. After running the script, connect locally by running `sliver`.

https://sudosoc.com/install

This script should work on Kali, Ubuntu, and RHEL (CentOS, etc) distributions of Linux.

**⚠️ OPSEC:** By default the Linux install script will bind the multiplayer listener to `:47443` on all interfaces. In current releases that is the WireGuard-protected multiplayer listener, so the outer service is UDP/47443 and the authenticated gRPC/mTLS server only exists inside the tunnel. Ensure your firewalls are properly configured if this is a concern, or reconfigure the server to bind to localhost if you only wish to allow local users. Publicly exposing the multiplayer listener still makes the server easier to discover and fingerprint.

### One Liner

```
curl https://sudosoc.com/install|sudo bash
```

- Installs server binary to `/root/sudosoc-server`
- Installs mingw
- Runs the server in daemon mode using systemd
- Installs client to `/usr/local/bin/sliver`
- Generates multiplayer configurations for all users with a `/home` directory

### Systemd Service

The following systemd configuration is used:

```ini
[Unit]
Description=Sliver
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=on-failure
RestartSec=3
User=root
ExecStart=/root/sudosoc-server daemon

[Install]
WantedBy=multi-user.target
```
