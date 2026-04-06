# WiFi Sniffer Web Control Panel v3

Web-based control panel for WiFi packet capture using OpenWrt Monitor Mode.
Supports simultaneous or individual capture of 2.4G / 5G / 6G bands.

**Version:** 3.0 | **Last Updated:** 2026-03-06

---

## What's New in v3

| Area | v2 | v3 |
|------|----|----|
| Architecture | Single `CaptureManager` (1000+ lines) | 5 focused services (~200 lines each) |
| Logging | 50+ `print()` calls, no levels | Python `logging` with rotating file output |
| SSH layer | `SSHConnectionPool` (not a real pool) | `SSHClient` with thread-safe `_command_lock` |
| Error handling | Bare `except:` blocks (swallow errors) | `except Exception as e:` + logged |
| Download code | Duplicated across 2 methods | Shared `FileDownloader` (single source) |
| Type hints | `set_cached_connection_status(bool)` for dict | Correct types + sentinel for `None` caching |
| Config | Hardcoded `SECRET_KEY`, `DEBUG=True` | `os.urandom` key, env-based debug flag |
| Frontend | Hardcoded `192.168.1.1`, polling timer leak | Host from API, timers properly cleaned up |
| Validation | POST endpoints accept any body | JSON validated, 400 on bad input |
| Tests | None | 37 smoke tests covering all layers |

### v3 Architecture

```
                  Browser
                    |
            WebSocket + REST
                    |
        +-----------+-----------+
        |     Flask App         |
        |  api.py    views.py   |
        +-----------+-----------+
                    |
     +--------------+--------------+
     |              |              |
CaptureService InterfaceService TimeSyncService
     |              |              |
     |         WifiConfigService   |
     |              |              |
     +------+-------+------+------+
            |              |
      FileDownloader   SSHClient
                           |
                     OpenWrt Router
```

Services are wired via `app.extensions` in the Flask app factory -- no globals needed
in route handlers.

---

## Quick Start

### Prerequisites

| Software | Purpose | Required |
|----------|---------|----------|
| Python 3.8+ | Run application | Yes |
| OpenWrt Router | Packet capture target (default `192.168.1.1`) | Yes |
| Wireshark | View `.pcap` files | Recommended |

**OpenWrt must have:**
- SSH enabled (Dropbear)
- Monitor mode configured
- `tcpdump` installed

### Install & Run

```powershell
# 1. Install dependencies (first time)
pip install -r requirements.txt

# 2. Start the v3 server
python wifi_sniffer_web_control_v3.py
# or double-click: start_server_v3.bat

# 3. Open browser at http://127.0.0.1:5000
```

### Standalone EXE (no Python needed)

Build with PyInstaller:

```powershell
cd build
# (update wifi_sniffer_v3.spec as needed, then)
pyinstaller wifi_sniffer_v3.spec
```

The resulting EXE runs a system-tray icon with "Open Web Panel", "Status", and "Exit" menu items.

---

## Configuration

All settings can be overridden via environment variables. Defaults work out of the box.

| Env Variable | Default | Description |
|---|---|---|
| `OPENWRT_HOST` | `192.168.1.1` | Router IP address |
| `OPENWRT_USER` | `root` | SSH username |
| `OPENWRT_PASSWORD` | *(none)* | SSH password (key-based auth by default) |
| `SSH_KEY_PATH` | *(none)* | Path to SSH private key |
| `SSH_PORT` | `22` | SSH port |
| `FLASK_PORT` | `5000` | Web server port |
| `FLASK_HOST` | `0.0.0.0` | Bind address (`127.0.0.1` for local only) |
| `FLASK_DEBUG` | `false` | Enable Flask debug mode |
| `FLASK_SECRET_KEY` | *(auto-generated)* | Session secret key |
| `SNIFFER_DOWNLOADS` | `~/Downloads` | Pcap download folder |
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `LOG_FILE` | *(none)* | Path for rotating log file |

### Port Configuration (multiple projects)

```powershell
$env:FLASK_PORT = 5002
python wifi_sniffer_web_control_v3.py
```

---

## Project Structure

```
Sniffer and Pcap Capture/
├── wifi_sniffer_v3/                   # v3 package
│   ├── __init__.py                   # App factory, SocketIO setup
│   ├── config.py                     # Environment-aware config
│   ├── logging_config.py             # Logging setup (console + file)
│   ├── cache.py                      # TTL cache with sentinel
│   ├── utils.py                      # Shared helpers
│   ├── ssh/
│   │   ├── client.py                # SSHClient (thread-safe)
│   │   └── commands.py              # Thin wrappers
│   ├── services/
│   │   ├── capture.py               # Start / stop / monitor
│   │   ├── interfaces.py            # Interface auto-detection
│   │   ├── time_sync.py             # PC-OpenWrt time sync
│   │   ├── wifi_config.py           # Channel / bandwidth / UCI
│   │   └── file_download.py         # Pcap download (shared)
│   ├── routes/
│   │   ├── api.py                   # REST API (validated)
│   │   └── views.py                 # Page routes
│   └── static/
│       ├── css/style.css            # Dark theme UI
│       └── js/app.js                # WebSocket + polling client
├── templates/
│   └── index.html                    # Main web UI
├── tests/
│   └── test_v3_smoke.py             # 37 smoke tests
├── wifi_sniffer_web_control_v3.py    # v3 entry point
├── start_server_v3.bat               # One-click launcher
├── build/
│   └── wifi_sniffer_app_v3.py       # Desktop app (system tray)
├── requirements.txt                  # Python dependencies
└── wifi_sniffer_v3/README.md         # This file
```

The v2 code (`wifi_sniffer/`) remains alongside v3 -- both versions coexist.

---

## Operation Guide

### 1. Start the Server

```
Double-click: start_server_v3.bat
```

Wait for the terminal to show `Running on http://...`, then the browser opens automatically.

### 2. Verify Connection

The header shows the router connection status:
- Green dot + `Connected` -- ready to capture
- Red dot + `Disconnected` -- click for diagnostics

### 3. Start Capture

| Action | Button | Effect |
|--------|--------|--------|
| Single band | **Start** on a band card | Starts tcpdump on that interface |
| All bands | **Start All Captures** | Starts tcpdump on ath0, ath1, ath2 |

Time is automatically synced to the router before the first capture starts.

### 4. Stop & Download

| Action | Button | Effect |
|--------|--------|--------|
| Single band | **Stop & Save** | Downloads that band's pcap |
| All bands | **Stop All & Download** | Downloads all pcap files |

Files are saved to `~/Downloads/` with the format `{Band}_sniffer_{YYYYMMDD_HHMMSS}.pcap`.

### 5. Analyse

Open the `.pcap` files in Wireshark. Set View -> Time Display Format -> **Date and Time of Day** to see absolute timestamps.

---

## Interface Auto-Detection

Different hardware units may swap 5G and 6G interfaces. The system auto-detects
on first connection by reading frequencies from `iwconfig`:

| Frequency | Band |
|-----------|------|
| < 3 GHz | 2G |
| 3 - 6 GHz | 5G |
| > 6 GHz | 6G |

Results are cached for 5 minutes. Click the **Detect** button in the header to
force re-detection.

### Default Mapping

| Band | Interface | UCI Radio | Bandwidth Options |
|------|-----------|-----------|-------------------|
| 2.4G | ath0 | wifi0 | HT20, HT40 |
| 5G | ath2 | wifi2 | EHT20, EHT40, EHT80, EHT160 |
| 6G | ath1 | wifi1 | EHT20, EHT40, EHT80, EHT160, EHT320 |

---

## Channel Configuration

### Via Web UI (recommended)

1. Select channel and bandwidth for each band from the dropdowns
2. Click **Apply Config & Restart WiFi**
3. The system applies settings without `wifi load`:
   - 2G / 5G: `iwconfig athX Channel N`
   - 6G: `cfg80211tool ath1 channel N 3`
4. Each band is verified via `iwconfig` after applying

### Via SSH (manual)

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.1.1

# View current settings
iwconfig

# Set channels via UCI
uci set wireless.wifi0.channel=6
uci set wireless.wifi0.htmode=HT40
uci set wireless.wifi2.channel=36
uci set wireless.wifi2.htmode=EHT160
uci set wireless.wifi1.channel=37
uci set wireless.wifi1.htmode=EHT320
uci commit wireless
wifi load
```

---

## File Split

For long capture sessions, enable file splitting to avoid oversized pcap files.

1. Toggle **Split Files by Size** in the header
2. Choose max file size: 50 / 100 / **200** (default) / 500 / 1000 MB
3. When stopped, parts are numbered: `2G_sniffer_20260306_143000_part001.pcap`, `...part002.pcap`, etc.

---

## Time Synchronization

OpenWrt routers without RTC battery lose their clock on reboot. The system:
- Auto-syncs PC time to the router before each capture
- Shows live offset in the header: `PC: HH:MM:SS | OpenWrt: HH:MM:SS`
- Displays a badge: **Synced** (< 2s offset), **+Ns** (warning), **+Nm** (error)

Click the **Sync** button anytime to force a manual sync.

---

## API Reference

All endpoints are prefixed with `/api`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/status` | Capture status for all bands |
| POST | `/start/<band>` | Start capture (2G, 5G, 6G) |
| POST | `/stop/<band>` | Stop capture and download |
| POST | `/start_all` | Start all bands |
| POST | `/stop_all` | Stop all and download |
| POST | `/config/<band>` | Set channel/bandwidth (JSON body) |
| POST | `/apply_config` | Apply all configs to OpenWrt |
| GET | `/get_wifi_config` | Current WiFi config (from UCI) |
| GET | `/test_connection` | SSH connection test (cached) |
| GET | `/diagnose` | Full connection diagnostics |
| GET | `/time_info` | PC and OpenWrt time + offset |
| POST | `/sync_time` | Force time sync |
| GET | `/file_split` | File split settings |
| POST | `/file_split` | Update file split (JSON body) |
| GET | `/interface_mapping` | Interface mapping + detection status |
| POST | `/detect_interfaces` | Force re-detection |

POST endpoints require `Content-Type: application/json` and return HTTP 400 on invalid body.

---

## Running Tests

```powershell
python -m pytest tests/test_v3_smoke.py -v
```

The test suite covers:
- All module imports (14 tests)
- Configuration values (4 tests)
- Cache behaviour including sentinel and TTL (5 tests)
- Service instantiation (5 tests)
- App factory, route registration, and input validation (8 tests)
- Platform utilities (1 test)

---

## Troubleshooting

### Cannot connect (Disconnected)

1. Click the red status dot to open the built-in diagnostic modal
2. Check: router powered on, PC on same network, SSH enabled on OpenWrt
3. Manual test:
   ```powershell
   ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-rsa root@192.168.1.1 "echo ok"
   ```

### Capture starts but no file downloaded

- Verify `tcpdump` is installed: `ssh root@192.168.1.1 "which tcpdump"`
- Check `/tmp` space: `ssh root@192.168.1.1 "df /tmp"`
- Confirm monitor mode: `ssh root@192.168.1.1 "iwconfig"`

### Small file (24 bytes)

No packets were captured. Verify:
- DUT is transmitting on the configured channel
- Interface is in monitor mode
- Channel and bandwidth are set correctly

### WebSocket not working

```powershell
pip install flask-socketio eventlet
```
If WebSocket fails, the app falls back to HTTP polling automatically.

### SSH key conflict

```powershell
ssh-keygen -R 192.168.1.1
```

### Timestamps mismatch in Wireshark

- In Wireshark: View -> Time Display Format -> **Date and Time of Day**
- Ensure the header shows **Synced** before starting capture

---

## Changelog

### v3.0 (2026-03-06)

- **Refactored**: Broke 1000-line `CaptureManager` into 5 services:
  `CaptureService`, `InterfaceService`, `TimeSyncService`, `WifiConfigService`, `FileDownloader`
- **Added**: Python `logging` module with configurable levels and optional rotating file handler;
  all `print()` calls replaced
- **Fixed**: `SSHClient` (renamed from `SSHConnectionPool`) now uses `_command_lock` for thread
  safety; removed unused `queue` import
- **Fixed**: Cache `set_cached_connection_status` type hint corrected from `bool` to `dict`;
  `get_or_compute` uses sentinel so `None`/`False` can be cached
- **Fixed**: All bare `except:` blocks replaced with `except Exception as e:` + logging
- **Fixed**: Frontend no longer hardcodes `192.168.1.1` -- host comes from API response;
  polling intervals are cleared before re-creation to prevent timer stacking
- **Improved**: `SECRET_KEY` auto-generated via `os.urandom`; `DEBUG_MODE` reads from
  `FLASK_DEBUG` env var (defaults to `false`)
- **Improved**: All POST endpoints validate JSON body and return HTTP 400 on invalid input
- **Improved**: File download logic de-duplicated into shared `FileDownloader`
- **Added**: `utils.py` with shared `get_subprocess_startupinfo()` (was duplicated in two files)
- **Added**: Comprehensive smoke test suite (`tests/test_v3_smoke.py`, 37 tests)
- **Added**: Desktop app v3 (`build/wifi_sniffer_app_v3.py`) with system tray support

### Previous Versions

See the project root `README.md` for v1.0 -- v2.2 changelog.
