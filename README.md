# WiFi Sniffer Control Panel v3

Windows-friendly control panel for OpenWrt monitor-mode packet capture across 2.4 GHz, 5 GHz, and 6 GHz bands.

This repository is now intentionally focused on the current `v3` code path. Older `v1/v2` code and duplicated build artifacts were removed so the repo is easier to maintain and deploy.

## Highlights

- Flask + Socket.IO web UI for capture control and status updates
- Session-safe router cleanup that only touches captures created by this app
- Environment-based configuration with `.env` support
- Windows launcher for building a deployable `.exe`
- Smoke and refactor tests covering imports, app boot, API validation, cache, and capture state

## Quick Start

```powershell
pip install -r requirements.txt
copy .env.example .env
python wifi_sniffer_web_control_v3.py
```

Or on Windows, double-click [start_server_v3.bat](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/start_server_v3.bat).

Default UI URL:

```text
http://127.0.0.1:5000
```

## Configuration

The app reads configuration from environment variables and automatically loads `.env` when present.

Start from [\.env.example](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/.env.example).

Common settings:

| Variable | Default | Purpose |
|---|---|---|
| `OPENWRT_HOST` | `192.168.1.1` | Router IP |
| `OPENWRT_USER` | `root` | SSH username |
| `SSH_KEY_PATH` | unset | SSH private key path |
| `SSH_PORT` | `22` | SSH port |
| `FLASK_HOST` | `0.0.0.0` | Web bind host |
| `FLASK_PORT` | `5000` | Web bind port |
| `FLASK_DEBUG` | `false` | Debug mode |
| `SNIFFER_DOWNLOADS` | `~/Downloads` | Local save folder |
| `LOG_LEVEL` | `INFO` | Log verbosity |
| `LOG_FILE` | unset | Optional log file |
| `APP_REMOTE_PREFIX` | `wifi_sniffer_capture` | Prefix for app-managed remote files |

## Windows EXE Build

The repository includes a PyInstaller-based build path for a Windows launcher executable.

Build steps:

```powershell
build\build_v3.bat
```

After a successful build, the packaged artifact is placed at:

```text
build\dist\WiFi_Sniffer_Control_Panel_v3.exe
```

The build script also copies:

- `.env.example`
- `README.md`
- `build\BUILD_README.md`

into `build\dist\` so the deployment folder is self-contained.

Detailed build notes are in [build\BUILD_README.md](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/build/BUILD_README.md).

## Deployment Notes

For another Windows PC:

1. Copy the contents of `build\dist\`
2. Create a `.env` file beside the `.exe`
3. Set the target router SSH settings in `.env`
4. Launch `WiFi_Sniffer_Control_Panel_v3.exe`

The packaged launcher starts the local web server and opens the browser automatically.

## Testing

Run the full local test suite:

```powershell
python -m pytest -q
```

Current local verification includes:

- 48 passing tests
- app factory boot
- route registration
- API validation smoke checks
- compile check via `python -m compileall`

## Repository Layout

```text
Sniffer and Pcap Capture/
|-- wifi_sniffer_v3/               Active application package
|   |-- routes/                    Flask API and view routes
|   |-- services/                  Capture, config, interface, download, time services
|   |-- ssh/                       SSH execution helpers
|   |-- static/                    CSS and JavaScript assets
|   |-- config.py                  Runtime configuration
|   |-- remote.py                  Shell-safe remote command builders
|   `-- cache.py                   TTL cache helpers
|-- templates/                     Shared HTML templates
|-- tests/                         Smoke and refactor tests
|-- build/                         Build assets, desktop wrapper source, and launcher
|-- wifi_sniffer_web_control_v3.py Web entry point
|-- start_server_v3.bat            Source-mode launcher
`-- .env.example                   Example configuration
```

## Technical Docs

See [wifi_sniffer_v3\README.md](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/wifi_sniffer_v3/README.md) for the v3 architecture, service layout, and API notes.
