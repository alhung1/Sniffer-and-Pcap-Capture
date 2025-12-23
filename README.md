# 📡 WiFi Sniffer Web Control Panel

Web-based control panel for WiFi packet capture using OpenWrt Monitor Mode. Supports simultaneous or individual capture of 2.4G / 5G / 6G bands.

**Version:** 1.7 | **Last Updated:** 2024-12-23

---

## ⚡ Quick Deployment Checklist

For deploying on a new computer, follow these steps:

| Step | Action | Verification |
|------|--------|--------------|
| 1 | Install Python 3.8+ (check "Add to PATH") | `python --version` |
| 2 | Connect PC to OpenWrt network | Ping 192.168.1.1 |
| 3 | Double-click `install.bat` | All [OK] messages |
| 4 | Double-click `start_server.bat` | Browser opens |
| 5 | Check header shows 🟢 Connected | Green dot |
| 6 | Check time shows ✓ Synced | Green badge |

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
3. Install required Python packages (Flask, Paramiko)
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

If your OpenWrt has a password set, edit `wifi_sniffer_web_control.py`:
```python
OPENWRT_PASSWORD = "your_password"  # Line ~24
```

---

## 🚀 Quick Start

### Method 1: One-Click Launch (Recommended)

Double-click **`start_server.bat`**, the script will:
1. Automatically check Python environment
2. Install required dependencies
3. Start web server
4. Automatically open browser (http://127.0.0.1:5000)

### Method 2: Manual Launch

```powershell
# 1. Navigate to project directory (where you copied the folder)
cd "path\to\Sniffer and Pcap Capture"

# 2. Install dependencies (first time only)
pip install -r requirements.txt

# 3. Start server
python wifi_sniffer_web_control.py

# 4. Open browser
# http://127.0.0.1:5000
```

---

## 🔌 Port 配置（多專案同時運行）

本專案預設使用 **Port 5000**。若需與其他專案同時運行，可透過環境變數修改 Port。

### 修改方式

**方法一：編輯 `start_server.bat`**
```batch
:: 找到這行，修改 Port 號碼
set FLASK_PORT=5000
```

**方法二：手動執行時設定環境變數**
```powershell
$env:FLASK_PORT=5002
python wifi_sniffer_web_control.py
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
├── wifi_sniffer_web_control.py   # Main application (Flask Web Control)
├── requirements.txt               # Python dependencies list
├── install.bat                    # First-time installation script
├── setup_ssh.bat                  # SSH connection setup tool
├── start_server.bat               # One-click launch script
└── README.md                      # This documentation
```

---

## 🎮 Operation Guide

### Step-by-Step Capture Procedure

#### 1. Start the Server
```
Double-click: start_server.bat
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
- Packet count updates every 3 seconds

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

### 🔄 Auto-Detection (NEW in v1.7)

**Problem:** Different hardware units may have different interface mappings:
- **Unit A:** 5G=ath2, 6G=ath1 (default)
- **Unit B:** 5G=ath1, 6G=ath2 (swapped)

**Solution:** The system now **automatically detects** the correct interface mapping when connecting to OpenWrt.

**How it works:**
1. On connection, the system queries `iwconfig` to read interface frequencies
2. Interfaces are automatically mapped based on detected frequency:
   - Frequency < 3 GHz → 2G
   - Frequency 3-6 GHz → 5G
   - Frequency > 6 GHz → 6G
3. UCI radio mapping (wifi0/wifi1/wifi2) is also auto-detected

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
   
   # Commit changes and restart WiFi
   uci commit wireless
   wifi
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

### SSH Connection Details

The system uses these SSH options for OpenWrt/Dropbear compatibility:
```
-o StrictHostKeyChecking=no
-o HostKeyAlgorithms=+ssh-rsa
-o PubkeyAcceptedAlgorithms=+ssh-rsa
```

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
**A:** Please verify:
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

### v1.7 (2024-12-23)
- **Added**: Auto-detect interface mapping for different hardware units
  - Automatically detects which athX interface corresponds to which band (2G/5G/6G)
  - Supports units with different interface configurations (e.g., ath1/ath2 swapped)
  - Detection via `iwconfig` frequency reading
  - UCI radio mapping (wifi0/wifi1/wifi2) also auto-detected
- **Added**: Interface mapping display in Web UI header
  - Shows current mapping: `2G=ath0 | 5G=ath2 | 6G=ath1`
  - Status badge: `✓ Auto-detected` or `Default`
  - Manual re-detect button
- **Added**: API endpoints for interface mapping
  - `GET /api/interface_mapping` - Get current mapping
  - `POST /api/detect_interfaces` - Force re-detection
- **Fixed**: Channel configuration now works correctly on different hardware units

### v1.6 (2024-12-23)
- **Added**: File split feature to prevent oversized capture files during long sessions
  - Toggle switch in UI to enable/disable file splitting
  - Configurable file size: 50MB, 100MB, 200MB (default), 500MB, 1GB
  - Uses tcpdump `-C` option for automatic file rotation
  - Automatic download of all split files when capture stops
  - Split files named: `{Band}_sniffer_{timestamp}_part001.pcap`
- **Added**: API endpoints for file split configuration
  - `GET /api/file_split` - Get current settings
  - `POST /api/file_split` - Update settings
- **Updated**: EXE build includes file split feature

### v1.5 (2024-12-22)
- **Added**: Environment variable port configuration (`FLASK_PORT`)
  - Allows running multiple Flask projects simultaneously
  - Default port: 5000
  - Configurable via `start_server.bat` or environment variable
- **Updated**: All batch files support port configuration

### v1.4 (2024-12-19)
- **Added**: Auto-detect current WiFi channel configuration on page load
  - Channel Configuration dropdowns now show actual OpenWrt settings
  - No more guessing what channel/bandwidth is currently configured
- **Added**: Notification when config is loaded from OpenWrt

### v1.3 (2024-12-19)
- **Added**: Automatic time synchronization before capture starts
  - PC time is synced to OpenWrt before each capture session
  - Ensures pcap timestamps match PC time for accurate log correlation
- **Added**: Time sync status display in header (PC time vs OpenWrt time)
- **Added**: Manual time sync button for on-demand synchronization
- **Added**: API endpoints: `/api/time_info` and `/api/sync_time`

### v1.2 (2024-12-19)
- **Fixed**: Multi-band simultaneous capture now works correctly
  - Previously, starting one band would kill other bands' tcpdump processes
  - Now each band's tcpdump is managed independently
- **Added**: Channel configuration via Web UI (Apply Config & Restart WiFi)
- **Added**: UCI command integration for frequency changes
- **Fixed**: Bandwidth options updated to EHT for 5G/6G bands

### v1.1 (2024-12-19)
- Fixed SSH connection for OpenWrt/Dropbear (legacy ssh-rsa support)
- Changed file download method from SCP to SSH pipe (OpenWrt compatibility)
- Improved tcpdump background process handling for BusyBox
- Added connection diagnostics feature
- Added real-time capture status monitoring

### v1.0 (2024-12-19)
- Initial release
- Support for 2.4G / 5G / 6G tri-band capture
- Web control interface
- Auto-save to Downloads folder
