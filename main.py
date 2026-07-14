import os
import sys
from scanner import scan_folder, calculate_risk_score, get_risk_level


# Display the main menu
def show_menu():
    print("\nSecureDrive Scanner")
    print("-------------------")
    print("1. Scan USB or folder")
    print("2. Exit")


# Get the menu choice and convert it to an integer
def get_menu_choice():
    try:
        choice = int(input("Choose an option: "))
        return choice
    except ValueError:
        return 0


# Ask the user for a path and check if it exists
def get_scan_path():
    scan_path = input("Enter USB or folder path: ").strip()

    if os.path.exists(scan_path):
        print("Path found:", scan_path)
        return scan_path

    print("Invalid path.")
    return None


# Display the scan results
def show_results(
    scanned_files,
    findings,
    skipped_items,
    risk_score,
    risk_level
):
    print("\nScan completed.")
    print("Total files scanned:", len(scanned_files))
    print("Total findings:", len(findings))
    print("Skipped items:", len(skipped_items))
    print("Risk score:", risk_score)
    print("Risk level:", risk_level)

    if len(findings) == 0:
        print("No risky file indicators were found.")
    else:
        print("\nRisky files found:")

        for finding in findings:
            print("\nFile:", finding.file_path)
            print("Finding:", finding.finding_type)
            print("Reason:", finding.reason)
            print("Risk points:", finding.risk_points)

    if len(skipped_items) > 0:
        print("\nSkipped items:")

        for item in skipped_items:
            print("-", item)


def main():
    while True:
        show_menu()
        choice = get_menu_choice()

        if choice == 1:
            scan_path = get_scan_path()

            if scan_path is not None:
                print("\nScanning files...")

                scanned_files, findings, skipped_items = scan_folder(scan_path)

                risk_score = calculate_risk_score(findings)
                risk_level = get_risk_level(risk_score)

                show_results(
                    scanned_files,
                    findings,
                    skipped_items,
                    risk_score,
                    risk_level
                )

        elif choice == 2:
            print("Exiting SecureDrive Scanner.")
            sys.exit()

        else:
            print("Invalid option. Please choose 1 or 2.")


if __name__ == "__main__":
    main()