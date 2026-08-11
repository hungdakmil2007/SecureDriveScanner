# SecureDrive Scanner

SecureDrive Scanner is a Python cybersecurity project created for ITSC203.

The program scans a USB drive or folder for possible risky files and sensitive information. It also calculates SHA256 hashes for suspicious files and can optionally check those hashes with VirusTotal.

The scanner is designed to be read-only. It does not execute, modify, delete, quarantine, or upload scanned files.

## Author

Nguyen Hung Tran

## Main Features

### Risky File Detection

The scanner checks for:

- Risky file extensions:
  - `.exe`
  - `.bat`
  - `.cmd`
  - `.ps1`
  - `.vbs`
  - `.js`
  - `.scr`
  - `.msi`
  - `.lnk`
  - `.url`

- Suspicious double extensions such as:
  - `invoice.pdf.exe`
  - `document.txt.bat`

- `autorun.inf` files

- Macro-enabled Microsoft Office files:
  - `.docm`
  - `.xlsm`
  - `.pptm`

### Sensitive Data Detection

The scanner can read supported text-based files:

- `.txt`
- `.csv`
- `.log`
- `.py`
- `.json`
- `.xml`
- `.html`

It checks for possible:

- Email addresses
- Phone numbers
- Password-related values
- API keys
- Tokens
- Private key indicators
- Canadian SIN-like numbers
- Credit-card-like numbers

Credit-card-like numbers are also checked using the Luhn algorithm to reduce false positives.

Sensitive values are masked before they are displayed or saved in the report.

Examples:

- `johnsmith@gmail.com` becomes `jo***@gmail.com`
- `403-123-4567` becomes `***-***-4567`
- Password values become `[MASKED]`
- API keys such as `ABCDEF123456` become `ABC***456`
- SIN-like numbers become `***-***-789`
- Card-like numbers become `**** **** **** 1111`

## SHA256 Hashing

Suspicious files are hashed using SHA256.

The scanner opens the file in binary read mode and processes it in small blocks. The file is never executed during hashing.

SHA256 hashes are calculated for files detected by the risky file checks.

## Optional VirusTotal Lookup

After suspicious files are hashed, the user can choose whether to perform an online VirusTotal lookup.

Only the SHA256 hash is sent to VirusTotal. The full file is not uploaded by SecureDrive Scanner.

The VirusTotal feature:

- Is optional
- Checks the local cache before making an API request
- Stores previous results in `vt_cache.json`
- Limits new VirusTotal requests during each scan
- Handles missing API keys
- Handles invalid API keys
- Handles API quota errors
- Handles connection errors
- Continues the local scan even if the online lookup cannot be completed

A VirusTotal result of `Hash not found` does not mean that the file is safe. It only means that VirusTotal did not return a known result for that hash.

## VirusTotal Cache

Previous VirusTotal results are stored locally in:

`vt_cache.json`

Before making a new API request, the program checks this file for an existing result.

If the hash has already been checked, the cached result is used instead of making another request.

This helps reduce unnecessary API usage.

The cache file is ignored by Git.

To force a new lookup for previously checked hashes, the user can delete `vt_cache.json`.

## Risk Scoring

Each finding receives risk points based on its type.

Current risk values include:

- Possible email address: 5 points
- Possible phone number: 5 points
- Risky file extension: 10 points
- Macro-enabled Office file: 15 points
- Possible password value: 20 points
- Suspicious double extension: 25 points
- Possible API key: 25 points
- Possible token: 25 points
- Possible SIN-like number: 25 points
- Possible private key: 30 points
- Possible credit-card-like number: 30 points
- Autorun file: 30 points
- VirusTotal malicious hash: 50 points

The displayed risk score is limited to 100.

Risk levels are:

- 0: No Findings
- 1-39: Low
- 40-69: Medium
- 70-100: High

## Text Report

After each scan, SecureDrive Scanner creates a text report inside the `reports` folder.

The report includes:

- Scan path
- Scan date and time
- Total files scanned
- Total findings
- Risky file findings
- Possible sensitive data findings
- Skipped items
- Files hashed
- VirusTotal results available
- Risk score
- Risk level
- Finding reasons
- Line numbers for sensitive data findings
- Masked sensitive evidence
- SHA256 hashes
- Optional VirusTotal results
- Recommendations
- Final recommendation

Example report name:

`scan_report_20260811_001500.txt`

## Project Structure

```text
SecureDriveScanner/
├── main.py
├── scanner.py
├── finding.py
├── sensitive_detector.py
├── hash_checker.py
├── virustotal_lookup.py
├── report.py
├── README.md
└── .gitignore
```

### main.py

Controls the main menu and overall program flow.

It:

- Gets the user menu choice
- Validates the scan path
- Starts the folder scan
- Controls the optional VirusTotal lookup
- Calculates the final risk score
- Displays the results
- Generates the text report

### scanner.py

Contains the main file scanning logic.

It:

- Recursively scans folders using `os.walk()`
- Checks risky extensions
- Checks suspicious double extensions
- Checks for `autorun.inf`
- Checks macro-enabled Office files
- Stores findings
- Calculates SHA256 hashes for suspicious files
- Calls the sensitive data detector
- Handles skipped files and errors

### finding.py

Contains the `Finding` class.

Each Finding object can store:

- File path
- Finding type
- Reason
- Risk points
- Line number
- Masked evidence

### sensitive_detector.py

Reads supported text-based files line by line and searches for possible sensitive information using regular expressions and other validation checks.

It includes detection and masking for:

- Email addresses
- Phone numbers
- Password-related values
- API keys
- Tokens
- Private key indicators
- SIN-like numbers
- Credit-card-like numbers

### hash_checker.py

Calculates SHA256 hashes for suspicious files.

Files are read in binary mode without being executed.

### virustotal_lookup.py

Handles the optional VirusTotal feature.

It:

- Reads the VirusTotal API key from an environment variable
- Checks the local cache
- Sends SHA256 hashes to VirusTotal
- Limits new API requests during a scan
- Stores successful and not-found results in the cache
- Handles API and connection errors

### report.py

Creates the final text report.

It separates:

- Risky File Findings
- Possible Sensitive Data Findings
- SHA256 Hash Results
- Skipped Items
- Final Recommendation

## Course Requirements

The project demonstrates the required Python concepts for ITSC203:

- Functions
- Classes
- Casting
- `os` module
- `sys` module
- File handling

The project also uses:

- Lists
- Dictionaries
- Sets
- Loops
- Exception handling
- Custom Python modules
- Regular expressions
- JSON
- SHA256 hashing

## How to Run

Python 3 is required.

Open a terminal inside the project folder.

### Windows

```powershell
python main.py
```

### Linux

```bash
python3 main.py
```

The program displays:

```text
SecureDrive Scanner by Nguyen Hung Tran
-------------------
1. Scan USB or folder
2. Exit
```

Choose option `1` and enter the path of the USB drive or folder that you want to scan.

Example Windows path:

```text
E:\USBTest
```

Example Linux path:

```text
/media/user/USB
```

## VirusTotal API Key

VirusTotal lookup is optional.

The API key is read from the environment variable:

`VT_API_KEY`

The API key should not be placed directly inside the Python source code.

### Windows PowerShell

For the current terminal session:

```powershell
$env:VT_API_KEY="YOUR_API_KEY"
```

To save the variable for the current Windows user:

```powershell
[Environment]::SetEnvironmentVariable("VT_API_KEY", "YOUR_API_KEY", "User")
```

After saving it permanently, open a new terminal before running the program.

To check the variable:

```powershell
echo $env:VT_API_KEY
```

If the API key is not available, the local scanner and SHA256 hashing still work normally.

## Safety and Scope

SecureDrive Scanner is designed as a read-only security assessment tool.

The program does not intentionally:

- Execute scanned files
- Modify scanned files
- Delete scanned files
- Quarantine scanned files
- Automatically open suspicious files
- Upload full files to VirusTotal

Only SHA256 hash values are used for the optional online VirusTotal lookup.

## Limitations

SecureDrive Scanner is not a replacement for antivirus or endpoint security software.

Current limitations include:

- The user must manually enter the USB or folder path.
- The scanner does not automatically detect every mounted USB device.
- Sensitive data detection is pattern-based and may produce false positives.
- Only supported text-based files are inspected for sensitive information.
- Encrypted or locked files cannot be inspected unless they are accessible.
- Password-protected archives are not inspected internally.
- Some unreadable files may be skipped.
- A SHA256 hash alone does not determine whether a file is malicious.
- A VirusTotal `Hash not found` result does not prove that a file is safe.
- Online VirusTotal lookup requires an Internet connection and a valid API key.
- VirusTotal API usage may be limited by the API account quota.

## Project Status

Phase 3 functionality includes:

- Recursive folder and USB scanning
- Risky file detection
- Double-extension detection
- Autorun detection
- Macro-enabled Office file detection
- Sensitive data detection
- Masked sensitive evidence
- SHA256 hashing
- Optional VirusTotal lookup
- Local VirusTotal caching
- API request limiting
- Improved risk scoring
- Error handling
- Detailed text reporting

## Disclaimer

SecureDrive Scanner is an educational cybersecurity project.

Detection results should be reviewed by the user and should not be treated as a guarantee that a file is safe or malicious.