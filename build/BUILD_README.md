# Windows Build Guide

This folder contains the assets and scripts used to package the v3 launcher into a Windows executable.

## Output

The build produces:

```text
build\dist\WiFi_Sniffer_Control_Panel_v3.exe
```

The build script also copies:

- `.env.example`
- `README.md`
- this build guide

into `build\dist\`.

## Prerequisites

- Windows
- Python available in `PATH`
- network access for `pip install`

## Build Command

From the repository root:

```powershell
build\build_v3.bat
```

## What The Build Script Does

1. installs runtime dependencies from `requirements.txt`
2. installs build dependencies from `build\requirements_build.txt`
3. runs PyInstaller with [build\wifi_sniffer_v3.spec](/C:/Users/alhung/Sniffer%20and%20Pcap%20Capture/build/wifi_sniffer_v3.spec)
4. copies deployment helper files into `build\dist\`

## Deployment

Copy the contents of `build\dist\` to the target Windows machine.

Recommended deployment folder contents:

- `WiFi_Sniffer_Control_Panel_v3.exe`
- `.env.example`
- `README.md`
- `BUILD_README.md`

Create a `.env` file beside the `.exe` before first launch.

## Troubleshooting

If build fails:

- confirm Python can import `PyInstaller`
- re-run `python -m pip install -r requirements.txt -r build\requirements_build.txt`
- make sure no antivirus tool is locking the previous `build\dist\` output
