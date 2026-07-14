# SecureDrive Scanner By Nguyen Hung Tran

SecureDrive Scanner is a Python program that scans a USB drive or selected folder for possible security risks.

The program uses read-only scanning. It does not open, run, or modify the files being scanned.

## Current Features

- Scan a USB drive or folder and its subfolders
- Check if the entered path is valid
- Detect risky file extensions
- Detect double-extension files
- Detect autorun.inf files
- Detect macro-enabled Office files
- Calculate a basic risk score
- Show the risk level
- Track skipped files and folder errors
- Create a text report with findings and recommendations
- Work with Windows and Linux folder paths

## Risky File Types

The current version checks for:

- .exe
- .bat
- .cmd
- .ps1
- .vbs
- .js
- .scr
- .msi
- .lnk
- .url

## Project Files

- `main.py` - Shows the menu and controls the program
- `scanner.py` - Scans files and checks security indicators
- `finding.py` - Stores information about each finding
- `report.py` - Creates the text report

## How to Run

Windows:

```powershell
python main.py