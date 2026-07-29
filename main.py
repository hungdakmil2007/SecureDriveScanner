#Author: Nguyen Hung Tran
#Final project - ITSC203

# Course requirement - OS module:
import os
# Course requirement - SYS module:
import sys
# Custom modules created for this project
from report import generate_report
from scanner import scan_folder, calculate_risk_score, get_risk_level



# Course requirement - Function:
#display the main menu
def show_menu():
    print("\nSecureDrive Scanner by Nguyen Hung Tran")
    print("-------------------")
    print("1. Scan USB or folder")
    print("2. Exit")


# Course requirement - Function and Casting:
#get the menu choice and convert it to an integer
def get_menu_choice():
    try:
        choice = int(input("Choose an option: "))
        return choice
    except ValueError:
        return 0


# Course requirement - Function and OS module:
#ask the user for a folder path and check if it is valid
def get_scan_path():
    scan_path = input("Enter USB or folder path: ").strip()
     # Use the OS module to validate the path
    if not os.path.exists(scan_path):
        print("The path does not exist.")
        return None

    if not os.path.isdir(scan_path):
        print("The path must be a USB drive or folder.")
        return None
    # Convert the path into a full absolute path
    scan_path = os.path.abspath(scan_path)

    print("Path found:", scan_path)
    return scan_path


# Course requirement - Function:
#display the scan results
def show_results(
    scanned_files,
    findings,
    skipped_items,
    risk_score,
    risk_level
):
    #scanned_files, findings, and skipped_items are lists
    print("\nScan completed.")
    print("Total files scanned:", len(scanned_files))
    print("Total findings:", len(findings))
    print("Skipped items:", len(skipped_items))
    print("Risk score:", risk_score)
    print("Risk level:", risk_level)

    if len(findings) == 0:
        print("No risky file indicators were found")
    else:
        print("\nRisky files found:")

        for finding in findings:
            print("\nFile:", finding.file_path)
            print("Finding:", finding.finding_type)
            print("Reason:", finding.reason)
            # Phase 3:
            # Display the line number and masked evidence when available
            if finding.line_number is not None:
                print("Line number:", finding.line_number)

            if finding.evidence is not None:
                print("Masked evidence:", finding.evidence)
            print("Risk points:", finding.risk_points)

    if len(skipped_items) > 0:
        print("\nSkipped items:")

        for item in skipped_items:
            print("-", item)

#keep displaying the menu until the user choose exit
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

                report_path = generate_report(
                    scan_path,
                    scanned_files,
                    findings,
                    skipped_items,
                    risk_score,
                    risk_level
                )
                print("\nText report saved to:", report_path)

        elif choice == 2:
            print("Exiting SecureDrive Scanner, have a sweet day!!!")
            # Course requirement - SYS module:
            sys.exit()

        else:
            print("Invalid option. Please choose 1 or 2.")


if __name__ == "__main__":
    main()