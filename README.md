# 📡 WiFi Sniffer Web Control Panel

Web-based control panel for WiFi packet capture using OpenWrt Monitor Mode. Supports simultaneous or individual capture of 2.4G / 5G / 6G bands.

**Version:** 2.2 | **Last Updated:** 2026-01-28

---

## ⚡ Quick Deployment Checklist

For deploying on a new computer, follow these steps:

| Step | Action | Verification |
|------|--------|--------------|
| 1 | Install Python 3.8+ (check "Add to PATH") | `python --version` |
| 2 | Connect PC to OpenWrt network | Ping 192.168.1.1 |
| 3 | Double-click `install.bat` | All [OK] messages |
| 4 | Double-click `start_server_v2.bat` | Browser opens |
| 5 | Check header shows 🟢 Connected | Green dot |
| 6 | Check time shows ✓ Synced | Green badge |

> **v2.0:** Major performance improvements! SSH connection pooling, WebSocket real-time updates, and async page loading for faster response on Windows 10/11.

---

## 🆕 What's New in v2.0

| Feature | v1 (Classic) | v2 (Performance) |
|---------|--------------|------------------|
| Page Load | 3-5 seconds | < 500ms |
| SSH Commands | New connection each time | Connection pooling |
| Status Updates | 5 sec polling | WebSocket (instant) |
| Interface Detection | 5-10 seconds | 2-3 seconds (cached) |
| Architecture | Single file (2600 lines) | Modular (10+ files) |

### v2 Performance Features
- **SSH Connection Pool** - Reuses connections, caches SSH executable path
- **WebSocket Real-time Updates** - No more polling, instant status changes
- **Caching Layer** - Connection status, interface mapping cached
- **Async Page Load** - Page renders immediately, data loads in background
- **Modular Architecture** - Easier to maintain and extend

---

## 📋 System Requirements

| Software | Purpose | Required |
|----------|---------|----------|
| Python 3.8+ | Run main application | ✅ Required |
| OpenWrt Router | Sniffer capture (192.168.1.1) | ✅ Required |
| Wireshark | View .pcap files | ⭐ Recommended |
| Tera Term | SSH connection for frequency config | ⭐ Recommended |

### OpenWrt Requirements
- IP Address: `192.168.1.1`
- SSH enabled (Dropbear)
- Monitor Mode configured
- `tcpdump` package installed

---

## 📦 First-Time Installation (New Computer Setup)

### Step 1: Download Required Software

| Software | Download Link |
|----------|---------------|
| Python | https://www.python.org/downloads/ |
| Wireshark | https://www.wireshark.org/download.html |
| Tera Term | https://github.com/TeraTermProject/teraterm/releases |

> ⚠️ **Important**: When installing Python, make sure to check **"Add Python to PATH"**

### Step 2: Run Automated Installation Script

Double-click **`install.bat`**, the script will automatically:
1. Check if Python is installed
2. Install and upgrade pip to latest version
3. Install required Python packages:
   - Flask, Paramiko (core)
   - Flask-SocketIO, Eventlet (v2 WebSocket support)
4. Check if Wireshark is installed
5. Provide SSH connection test

> **Note**: Windows 10/11 includes OpenSSH by default. If SSH is not available, enable it via:
> Settings → Apps → Optional Features → Add OpenSSH Client

### Step 3: Verify SSH Connection

The system uses Windows native SSH with legacy algorithm support for OpenWrt/Dropbear compatibility.

**Test SSH manually:**
```powershell
ssh -o StrictHostKeyChecking=no -o HostKeyAlgorithms=+ssh-rsa root@192.168.1.1 "echo connected"
```

The system uses Windows native SSH which works automatically with OpenWrt's default configuration (no password). 

If your OpenWrt requires a password, you can either:
1. **Set up SSH key authentication** (recommended)
2. **Edit the config file**: Set `OPENWRT_PASSWORD = "your_password"` in `wifi_sniffer/config.py`

---

## 🚀 Quick Start

### Method 1: v2 One-Click Launch (Recommended)

Double-click **`start_server_v2.bat`**, the script will:
1. Automatically check Python environment
2. Install required dependencies
3. Start web server with WebSocket support
4. Automatically open browser (http://127.0.0.1:5000)

### Method 2: v1 Classic Launch

Double-click **`start_server.bat`** for the classic v1 experience.

### Method 3: Standalone EXE (No Python Required)

| Version | File | Size |
|---------|------|------|
| v1 | `build\dist\WiFi_Sniffer_Control_Panel.exe` | 24.7 MB |
| **v2** | `build\dist\WiFi_Sniffer_Control_Panel_v2.exe` | **38.6 MB** |
| v3 | `build\dist\WiFi_Sniffer_Control_Panel_v3.exe` | 38.6 MB |

Build the EXE: run `build\build_v2.bat` from the project directory. Double-click the EXE - no Python installation needed!

### Method 4: Manual Launch

```powershell
# 1. Navigate to project directory
cd "path\to\Sniffer and Pcap Capture"

# 2. Install dependencies (first time only)
pip install -r requirements.txt

# 3. Start server (choose one)
python wifi_sniffer_web_control_v2.py   # v2 (recommended)
python wifi_sniffer_web_control.py      # v1 (classic)

# 4. Open browser
# http://127.0.0.1:5000
```

---

## 🔌 Port 配置（多專案同時運行）

本專案預設使用 **Port 5000**。若需與其他專案同時運行，可透過環境變數修改 Port。

### 修改方式

**方法一：編輯 `start_server_v2.bat`**
```batch
:: 找到這行，修改 Port 號碼
set FLASK_PORT=5000
```

**方法二：手動執行時設定環境變數**
```powershell
$env:FLASK_PORT=5002
python wifi_sniffer_web_control_v2.py
```

### 專案 Port 對照表

| 專案 | 預設 Port | 網址 |
|------|-----------|------|
| WiFi Sniffer Control Panel | `5000` | http://127.0.0.1:5000 |
| WiFi PCAP Analyzer | `5001` | http://127.0.0.1:5001 |

> **提示**：若 EXE 檔案也需要使用不同 Port，需設定環境變數後執行，或重新編譯 EXE。

---

## 📁 File Structure

```
Sniffer and Pcap Capture/
├── wifi_sniffer/                      # v2 Modular Package
│   ├── __init__.py                    # Flask app factory
│   ├── config.py                      # Centralized configuration
│   ├── cache.py                       # Caching layer
│   ├── ssh/
│   │   ├── connection.py              # SSH connection pool
│   │   └── commands.py                # SSH command helpers
│   ├── capture/
│   │   └── manager.py                 # Capture state management
│   ├── routes/
│   │   ├── api.py                     # REST API endpoints
│   │   └── views.py                   # Page routes
│   └── static/
│       ├── css/style.css              # Extracted CSS (cacheable)
│       └── js/app.js                  # Extracted JS (WebSocket)
├── templates/
│   └── index.html                     # HTML template
├── wifi_sniffer_web_control_v2.py     # v2 entry point
├── wifi_sniffer_web_control.py        # v1 classic (single file)
├── requirements.txt                   # Python dependencies
├── install.bat                        # One-click installation
├── start_server_v2.bat                # v2 launcher
├── start_server.bat                   # v1 launcher
├── setup_ssh.bat                      # SSH connection setup
├── build/
│   ├── dist/
│   │   ├── WiFi_Sniffer_Control_Panel_v2.exe
│   │   └── WiFi_Sniffer_Control_Panel.exe
│   ├── build_v2.bat                   # Build v2 EXE
│   └── build.bat                      # Build v1 EXE
└── README.md                          # This documentation
```

---

## 🎮 Operation Guide

### Step-by-Step Capture Procedure

#### 1. Start the Server
```
Double-click: start_server_v2.bat
```
- Wait for terminal to show "Running on http://127.0.0.1:5000"
- Browser will open automatically

#### 2. Verify Connection
- Check the header shows: `🟢 192.168.1.1 Connected`
- If disconnected, click on the status to run diagnostics

#### 3. Start Capture

| Action | Button | Result |
|--------|--------|--------|
| Capture single band | Click `Start` on band card | Starts tcpdump on that interface |
| Capture all bands | Click `Start All Captures` | Starts tcpdump on ath0, ath1, ath2 |

- Status badge changes from `IDLE` to `CAPTURING`
- Duration timer starts counting
- Packet count updates in real-time (WebSocket in v2)

#### 4. Stop and Download

| Action | Button | Result |
|--------|--------|--------|
| Stop single band | Click `Stop & Save` on band card | Downloads that band's pcap |
| Stop all bands | Click `Stop All & Download` | Downloads all pcap files |

- Files are automatically saved to `C:\Users\[Username]\Downloads\`
- Filename format: `{Band}_sniffer_{YYYYMMDD}_{HHMMSS}.pcap`

#### 5. Analyze with Wireshark
```
Open the downloaded .pcap files with Wireshark for analysis
```

---

## 🔧 Interface Mapping

### Default Mapping

| Band | OpenWrt Interface | SSID | Frequency Range |
|------|-------------------|------|-----------------|
| 2.4G | ath0 | RFLab2g | 2.4 GHz (CH 1-14) |
| 5G | ath2 | RFLab5g | 5 GHz (CH 36-165) |
| 6G | ath1 | RFLab6g | 6 GHz (CH 1-233) |

### 🔄 Auto-Detection

**Problem:** Different hardware units may have different interface mappings:
- **Unit A:** 5G=ath2, 6G=ath1 (default)
- **Unit B:** 5G=ath1, 6G=ath2 (swapped)

**Solution:** The system **automatically detects** the correct interface mapping when connecting to OpenWrt.

**How it works:**
1. On connection, the system queries `iwconfig` to read interface frequencies
2. Interfaces are automatically mapped based on detected frequency:
   - Frequency < 3 GHz → 2G
   - Frequency 3-6 GHz → 5G
   - Frequency > 6 GHz → 6G
3. UCI radio mapping (wifi0/wifi1/wifi2) is also auto-detected
4. **v2**: Results are cached for 5 minutes for faster subsequent loads

**Web UI Indicators:**
- Header shows: `🔗 Interface: 2G=ath0 | 5G=ath2 | 6G=ath1`
- Badge shows: `✓ Auto-detected` (green) or `Default` (gray)
- Click `🔍 Detect` button to manually re-detect

**API Endpoints:**
- `GET /api/interface_mapping` - Get current mapping and detection status
- `POST /api/detect_interfaces` - Force re-detection of interface mapping

---

## 📻 Frequency Configuration

### Method 1: Web Interface (Recommended)

1. **Select Channel & Bandwidth** for each band using the dropdown menus
2. Click **"Apply Config & Restart WiFi"** button
3. Wait for the modal to show "Configuration Complete"
4. Start capturing

### Method 2: Manual via Tera Term / SSH

1. **Open Tera Term** or SSH terminal

2. **Connect to OpenWrt**
   ```bash
   ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.1.1
   ```

3. **View Current Configuration**
   ```bash
   iwconfig
   uci show wireless | grep -E "channel|htmode"
   ```

4. **Execute Frequency Commands**
   
   ```bash
   # 2.4G (wifi0) - Set channel and bandwidth
   uci set wireless.wifi0.channel=6
   uci set wireless.wifi0.htmode=HT40
   
   # 5G (wifi2) - Set channel and bandwidth  
   uci set wireless.wifi2.channel=36
   uci set wireless.wifi2.htmode=EHT160
   
   # 6G (wifi1) - Set channel and bandwidth
   uci set wireless.wifi1.channel=37
   uci set wireless.wifi1.htmode=EHT320
   
   # Commit changes and reload WiFi
   uci commit wireless
   wifi load
   ```

5. **Wait for interfaces to come back up** (~15-30 seconds)
   ```bash
   # Verify interfaces are ready
   iwconfig
   ```

### UCI Radio Mapping

| Band | UCI Radio | Interface | Bandwidth Options |
|------|-----------|-----------|-------------------|
| 2.4G | wifi0 | ath0 | HT20, HT40 |
| 5G | wifi2 | ath2 | EHT20, EHT40, EHT80, EHT160 |
| 6G | wifi1 | ath1 | EHT20, EHT40, EHT80, EHT160, EHT320 |

---

## 🔄 Technical Details

### How It Works

1. **Web Interface** (Flask) provides control panel at http://127.0.0.1:5000
2. **SSH Commands** are executed via Windows native SSH with legacy algorithm support
3. **tcpdump** runs on OpenWrt to capture packets to `/tmp/{band}.pcap`
4. **File Download** uses SSH pipe (`ssh cat /tmp/file > local_file`) since OpenWrt lacks sftp-server
5. **Auto-cleanup** removes remote pcap files after successful download

### v2 Architecture (Performance)

```
┌─────────────────────────────────────────────────────────────┐
│                     Frontend (Browser)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐  │
│  │Static CSS│  │Static JS │  │  WebSocket Client        │  │
│  │(Cached)  │  │(Cached)  │  │  (Real-time updates)     │  │
│  └──────────┘  └──────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Backend (Flask)                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐  │
│  │Blueprints│  │Cache     │  │  WebSocket Server        │  │
│  │(Routes)  │  │Layer     │  │  (Flask-SocketIO)        │  │
│  └──────────┘  └──────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    SSH Layer                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Connection Pool (Singleton)                          │  │
│  │  - Cached SSH executable path                         │  │
│  │  - Thread-safe command execution                      │  │
│  │  - Reusable connections                               │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    OpenWrt Router                            │
│                    192.168.1.1                               │
└─────────────────────────────────────────────────────────────┘
```

### SSH Connection Details

The system uses **Windows native SSH** (`C:\Windows\System32\OpenSSH\ssh.exe`) for best compatibility with OpenWrt/Dropbear.

**SSH options used:**
```
-o StrictHostKeyChecking=no
-o HostKeyAlgorithms=+ssh-rsa
-o ConnectTimeout=10
```

**Compatibility:**
- ✅ Windows 10 21H2 (OpenSSH 8.1p1)
- ✅ Windows 11 (newer OpenSSH)
- ✅ OpenWrt with Dropbear SSH server

### Capture Command

On OpenWrt, the following command is executed:
```bash
# Normal mode (continuous capture)
tcpdump -i {interface} -U -s0 -w /tmp/{band}.pcap &

# With file splitting enabled (e.g., 200MB per file)
tcpdump -i {interface} -U -s0 -w /tmp/{band}.pcap -C 200 &
```

- `-i {interface}` - Capture on specific interface (ath0/ath1/ath2)
- `-U` - Unbuffered output (write packets immediately)
- `-s0` - Capture full packet (no truncation)
- `-w` - Write to file
- `-C {size}` - Rotate file after reaching specified size (in MB)

### File Split Feature

**Why use file splitting?**
During long capture sessions, pcap files can grow very large, making them difficult to handle and analyze. The file split feature automatically rotates capture files when they reach a specified size.

**How to use:**
1. Look for the **"Split Files by Size"** toggle in the header area
2. Enable the toggle to activate file splitting
3. Select maximum file size: 50MB, 100MB, **200MB (default)**, 500MB, or 1GB
4. When disabled, capture continues to a single file (no size limit)

**File naming with split enabled:**
```
Downloads/
├── 2G_sniffer_20241223_143000_part001.pcap  (200 MB)
├── 2G_sniffer_20241223_143000_part002.pcap  (200 MB)
├── 2G_sniffer_20241223_143000_part003.pcap  (50 MB)
└── ...
```

**API endpoints:**
- `GET /api/file_split` - Get current file split configuration
- `POST /api/file_split` - Update file split settings (enabled, size_mb)

### Time Synchronization

**Why is this important?**
Pcap files contain timestamps generated by the OpenWrt router. If the router's system time differs from your PC, the timestamps in Wireshark won't match your other logs.

**How it works:**
1. Before each capture session starts, the system automatically syncs PC time to OpenWrt
2. The header displays real-time comparison: `🕐 PC: HH:MM:SS | OpenWrt: HH:MM:SS`
3. Status badge shows:
   - ✓ **Synced** (within 2 seconds)
   - **±Ns** (warning, few seconds off)
   - **±Nm** (error, minutes off - needs sync)

**Manual sync:** Click the 🔄 Sync button in the header to force time synchronization.

---

## ❓ Troubleshooting

### Q: Shows "Disconnected" - Cannot connect?
**A:** Try these steps:

1. **Click on "Disconnected" for detailed diagnosis**
   - Shows: Ping test, SSH key detection, specific error message
   - Provides targeted solution based on diagnosis

2. **Manual verification:**
   - OpenWrt router is powered on with IP 192.168.1.1
   - Your computer is connected to OpenWrt network
   - SSH service is enabled on OpenWrt
   - Test with: `ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.1.1 "echo test"`

### Q: Capture starts but no file downloaded?
**A:** Check:
- tcpdump is installed on OpenWrt (`which tcpdump`)
- Sufficient space in /tmp on OpenWrt
- Interface is in monitor mode (`iwconfig`)

### Q: Small file size (24 bytes)?
**A:** This means no packets were captured on that band. Verify:
- DUT is actively transmitting on that frequency
- Interface is set to correct channel
- Monitor mode is properly configured

### Q: SSH connection works in Tera Term but not in web panel?
**A:** The web panel uses Windows native SSH. Ensure:
- OpenSSH is installed on Windows
- Run: `ssh -V` to verify
- Legacy algorithm support is enabled in the code

### Q: How to clear SSH known_hosts entry?
**A:** If SSH connection fails due to key change, run:
```powershell
ssh-keygen -R 192.168.1.1
```

### Q: Pcap timestamps don't match PC time in Wireshark?
**A:** Two things to check:

1. **Wireshark display format** - By default shows relative time (0.000000)
   - Go to: View → Time Display Format → **Date and Time of Day**
   
2. **Time not synced** - Check header shows "✓ Synced"
   - If not synced, click 🔄 Sync button
   - Or start a new capture (auto-syncs before capture)

### Q: Time keeps drifting on OpenWrt?
**A:** OpenWrt may not have RTC battery, time resets on reboot. Solutions:
- The tool auto-syncs before each capture session
- Manually click 🔄 Sync in header anytime
- Consider setting up NTP on OpenWrt for persistent time

### Q: v2 WebSocket not working?
**A:** Check if Flask-SocketIO is installed:
```powershell
pip install flask-socketio eventlet
```
If WebSocket fails, the app automatically falls back to polling mode.

---

## 📊 Output Example

After successful capture, you'll see:

**Normal mode (single file per band):**
```
Downloads/
├── 2G_sniffer_20251223_121737.pcap  (5,209 bytes)
├── 5G_sniffer_20251223_121741.pcap  (9,811 bytes)
└── 6G_sniffer_20251223_121744.pcap  (3,456 bytes)
```

**With file split enabled (multiple files per band):**
```
Downloads/
├── 2G_sniffer_20251223_143000_part001.pcap  (200 MB)
├── 2G_sniffer_20251223_143000_part002.pcap  (200 MB)
├── 2G_sniffer_20251223_143000_part003.pcap  (50 MB)
├── 5G_sniffer_20251223_143005_part001.pcap  (200 MB)
├── 5G_sniffer_20251223_143005_part002.pcap  (150 MB)
└── 6G_sniffer_20251223_143010_part001.pcap  (75 MB)
```

---

## 📞 Technical Support

If you encounter issues, please collect:
- Python version: `python --version`
- Dependencies: `pip list`
- SSH test: `ssh -v -o HostKeyAlgorithms=+ssh-rsa root@192.168.1.1 "echo test"`
- OpenWrt interfaces: `ssh root@192.168.1.1 "iwconfig"`

---

## 🔄 Changelog

### v2.2 (2026-01-28)
- **Optimized**: Channel apply flow now uses iwconfig (2G/5G) and cfg80211tool (6G) directly — no `wifi load` required
  - 2G/5G: `iwconfig athX Channel N`
  - 6G: `cfg80211tool ath1 channel N 3`
  - Faster channel switching without full WiFi restart
- **Optimized**: Reduced SSH round-trips during channel verification
  - `get_current_channel_from_iwconfig()` now uses single SSH call with Python regex parsing
  - Saves 2-4 SSH calls per Apply Config operation
- **Improved**: SSH now uses publickey-only authentication (no password prompts or "password error" messages)
- **Improved**: Frontend sends 3 config POSTs in parallel using `Promise.all` for faster UI response
- **Improved**: UI tooltip on "Apply Config" button explains runtime vs UCI channel difference
- **Cleanup**: Removed unused `apply_2g_5g_with_iwconfig()` function to reduce code duplication

### v2.1 (2026-01-02)
- **Fixed**: Channel configuration now properly applies to OpenWrt
  - Changed WiFi reload command from `wifi` to `wifi load` for correct channel application
  - Fixed both v1 and v2 versions
- **Fixed**: Auto-read current channel/bandwidth from OpenWrt on startup
  - Program now detects and displays actual channel settings for all three bands
  - UI dropdowns automatically sync with OpenWrt configuration
- **Improved**: UCI detection includes htmode (bandwidth) in addition to channel
- **Improved**: Frontend auto-adds missing channel/bandwidth options if not in dropdown

### v2.0 (2026-01-02)
- **NEW**: Complete architecture refactor for performance
  - Modular package structure (`wifi_sniffer/`)
  - SSH connection pooling (cached executable path, reusable connections)
  - Caching layer for connection status and interface mapping
  - Async page loading (no blocking on SSH test)
- **NEW**: WebSocket real-time updates via Flask-SocketIO
  - Instant status updates (no more 5-second polling)
  - Automatic fallback to polling if WebSocket unavailable
- **NEW**: Separate static files for browser caching
  - CSS and JS extracted from Python code
  - Faster page loads on repeat visits
- **NEW**: Standalone EXE v2 with all performance improvements
  - `build\dist\WiFi_Sniffer_Control_Panel_v2.exe`
  - System tray support with status monitoring
- **IMPROVED**: Windows 10 Pro performance significantly improved
  - Page load: 3-5s → <500ms
  - SSH commands: 1-3s → 200-500ms (pooled)
- **UPDATED**: install.bat now installs all v2 dependencies

### v1.9 (2024-12-27)
- **Fixed**: Root cause of SSH connection issues on Windows 10 21H2
  - Removed `CREATE_NO_WINDOW` flag that was blocking SSH authentication
  - Simplified SSH command to use minimal options for best Dropbear compatibility
  - Auto-detect SSH executable path on Windows
- **Simplified**: Removed password input UI (no longer needed)
  - Removed `/api/set_password` endpoint
  - Removed password input box from web interface
  - System now uses native Windows SSH which handles authentication automatically
- **Simplified**: Removed paramiko-based SSH functions
  - All SSH operations now use system `ssh.exe` for best compatibility
  - Cleaner codebase with ~700 lines removed
- **Improved**: Better cross-platform Windows compatibility
  - Works on Windows 10 21H2 with OpenSSH 8.1p1
  - Works on Windows 11 with newer OpenSSH versions

### v1.8 (2024-12-27)
- **Added**: Web-based password input for easier setup on new computers
- **Added**: Enhanced connection diagnostics
- **Added**: Dual-track SSH authentication
- **Fixed**: SSH compatibility with older OpenSSH versions (e.g., 8.1p1)

### v1.7 (2024-12-23)
- **Added**: Auto-detect interface mapping for different hardware units
- **Added**: Interface mapping display in Web UI header
- **Added**: API endpoints for interface mapping
- **Fixed**: Channel configuration now works correctly on different hardware units

### v1.6 (2024-12-23)
- **Added**: File split feature to prevent oversized capture files during long sessions
- **Added**: API endpoints for file split configuration
- **Updated**: EXE build includes file split feature

### v1.5 (2024-12-22)
- **Added**: Environment variable port configuration (`FLASK_PORT`)
- **Updated**: All batch files support port configuration

### v1.4 (2024-12-19)
- **Added**: Auto-detect current WiFi channel configuration on page load
- **Added**: Notification when config is loaded from OpenWrt

### v1.3 (2024-12-19)
- **Added**: Automatic time synchronization before capture starts
- **Added**: Time sync status display in header
- **Added**: Manual time sync button
- **Added**: API endpoints: `/api/time_info` and `/api/sync_time`

### v1.2 (2024-12-19)
- **Fixed**: Multi-band simultaneous capture now works correctly
- **Added**: Channel configuration via Web UI
- **Added**: UCI command integration for frequency changes
- **Fixed**: Bandwidth options updated to EHT for 5G/6G bands

### v1.1 (2024-12-19)
- Fixed SSH connection for OpenWrt/Dropbear (legacy ssh-rsa support)
- Changed file download method from SCP to SSH pipe
- Improved tcpdump background process handling
- Added connection diagnostics feature
- Added real-time capture status monitoring

### v1.0 (2024-12-19)
- Initial release
- Support for 2.4G / 5G / 6G tri-band capture
- Web control interface
- Auto-save to Downloads folder
