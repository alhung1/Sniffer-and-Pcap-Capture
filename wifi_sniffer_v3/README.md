# WiFi Sniffer v3 Technical Notes

This package contains the active `v3` implementation of the WiFi Sniffer Control Panel.

## Architecture

`v3` keeps the public product behavior familiar, but internally moves the app toward smaller and safer units:

- `config.py`
  Single runtime configuration source with `.env` loading and validation
- `remote.py`
  Centralized band validation, interface validation, session id generation, and shell-safe OpenWrt command construction
- `services/capture.py`
  Session-aware capture lifecycle management
- `services/file_download.py`
  Download and cleanup of app-managed pcap files only
- `services/interfaces.py`
  Interface and UCI radio detection
- `services/time_sync.py`
  Router time synchronization
- `services/wifi_config.py`
  Channel and bandwidth application logic
- `routes/api.py`
  REST API with input validation and consistent JSON error handling

## Runtime Flow

1. [wifi_sniffer_web_control_v3.py](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/wifi_sniffer_web_control_v3.py) or [build\wifi_sniffer_app_v3.py](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/build/wifi_sniffer_app_v3.py) starts the app
2. [wifi_sniffer_v3\__init__.py](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/wifi_sniffer_v3/__init__.py) creates the Flask app, loads config, sets up Socket.IO, and wires services into `app.extensions`
3. The frontend calls `/api/test_connection` and `/api/interface_mapping`
4. Capture start generates an app-specific session id and remote file names
5. Status polling and WebSocket updates expose both backward-compatible `packets` and the clearer `estimated_packets`
6. Stop and cleanup only touch files and PIDs created by this application

## Safety Improvements In Current v3

- `.env` support with startup validation
- no global `killall tcpdump` cleanup
- no blanket deletion of `/tmp/*.pcap`
- per-session remote PID tracking
- centralized shell quoting and remote path generation
- duplicate start/stop protection with explicit `starting` and `stopping` state
- API input validation for band, channel, bandwidth, integer fields, and booleans

## API Notes

Important status fields:

- `running`
- `duration`
- `packets`
- `estimated_packets`
- `file_size_bytes`
- `pending_action`
- `state`
- `session_id`

`packets` remains for compatibility. It is currently derived from file size and should be treated as an estimate.

## Testing

Current tests live in:

- [tests\test_v3_smoke.py](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/tests/test_v3_smoke.py)
- [tests\test_v3_refactor.py](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/tests/test_v3_refactor.py)

Run everything with:

```powershell
python -m pytest -q
```

## Build Notes

The Windows packaging flow is documented in [build\BUILD_README.md](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/build/BUILD_README.md). The repo keeps [build\wifi_sniffer_app_v3.py](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/build/wifi_sniffer_app_v3.py) as the richer desktop wrapper source, while the packaged `.exe` uses a lighter launcher for reliability.
