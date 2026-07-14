import os
from finding import Finding


# Risky file types that the scanner will check
RISKY_EXTENSIONS = {
    ".exe": "Executable file",
    ".bat": "Batch script",
    ".cmd": "Command script",
    ".ps1": "PowerShell script",
    ".vbs": "Visual Basic script",
    ".js": "JavaScript file",
    ".scr": "Screen saver executable",
    ".msi": "Windows installer",
    ".lnk": "Shortcut file",
    ".url": "Internet shortcut"
}

# Common file types that may be used to disguise a risky file
DISGUISED_EXTENSIONS = {
    ".pdf",
    ".txt",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx"
}

# Office file types that can contain macros
MACRO_EXTENSIONS = {
    ".docm": "Macro-enabled Word document",
    ".xlsm": "Macro-enabled Excel workbook",
    ".pptm": "Macro-enabled PowerPoint presentation"
}


# Check if a file has a risky extension
def check_risky_extension(file_path):
    extension = os.path.splitext(file_path)[1].lower()

    if extension in RISKY_EXTENSIONS:
        reason = RISKY_EXTENSIONS[extension]

        finding = Finding(
            file_path,
            "Risky file type",
            reason,
            10
        )

        return finding

    return None

# Check for a risky file hidden behind another extension
def check_double_extension(file_path):
    file_name = os.path.basename(file_path).lower()

    name_without_last_extension, last_extension = os.path.splitext(file_name)
    second_extension = os.path.splitext(name_without_last_extension)[1]

    if (
        last_extension in RISKY_EXTENSIONS
        and second_extension in DISGUISED_EXTENSIONS
    ):
        reason = "Risky file hidden behind " + second_extension

        finding = Finding(
            file_path,
            "Double extension",
            reason,
            25
        )

        return finding

    return None

# Check if the file is autorun.inf
def check_autorun_file(file_path):
    file_name = os.path.basename(file_path).lower()

    if file_name == "autorun.inf":
        finding = Finding(
            file_path,
            "Autorun file",
            "Autorun file found on removable storage",
            30
        )

        return finding

    return None

# Check if an Office file can contain macros
def check_macro_file(file_path):
    extension = os.path.splitext(file_path)[1].lower()

    if extension in MACRO_EXTENSIONS:
        reason = MACRO_EXTENSIONS[extension]

        finding = Finding(
            file_path,
            "Macro-enabled Office file",
            reason,
            15
        )

        return finding

    return None

# Scan all files inside the selected folder and subfolders
def scan_folder(scan_path):
    scanned_files = []
    findings = []
    skipped_items = []

    # Save folder errors instead of stopping the program
    def handle_scan_error(error):
        skipped_path = error.filename

        if skipped_path is None:
            skipped_path = "Unknown path"

        skipped_items.append(
            skipped_path + " | " + str(error)
        )

    for root, folders, files in os.walk(
        scan_path,
        onerror=handle_scan_error
    ):
        for file_name in files:
            file_path = os.path.join(root, file_name)

            try:
                # Skip paths that are not regular files
                if not os.path.isfile(file_path):
                    skipped_items.append(
                        file_path + " | Not a regular file"
                    )
                    continue

                scanned_files.append(file_path)

                risky_finding = check_risky_extension(file_path)

                if risky_finding is not None:
                    findings.append(risky_finding)

                double_extension_finding = check_double_extension(file_path)

                if double_extension_finding is not None:
                    findings.append(double_extension_finding)

                autorun_finding = check_autorun_file(file_path)

                if autorun_finding is not None:
                    findings.append(autorun_finding)

                macro_finding = check_macro_file(file_path)

                if macro_finding is not None:
                    findings.append(macro_finding)

            except OSError as error:
                skipped_items.append(
                    file_path + " | " + str(error)
                )

    return scanned_files, findings, skipped_items

# Calculate the total risk score from all findings
def calculate_risk_score(findings):
    total_score = 0

    for finding in findings:
        total_score += finding.risk_points

    # Keep the displayed score between 0 and 100
    return min(total_score, 100)


# Convert the risk score into a risk level
def get_risk_level(risk_score):
    if risk_score == 0:
        return "No findings"
    elif risk_score < 40:
        return "Low"
    elif risk_score < 70:
        return "Medium"
    else:
        return "High"