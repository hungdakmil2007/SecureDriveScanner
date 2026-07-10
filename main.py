import os
import sys


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


# Scan all files inside the selected folder and its subfolders
def scan_folder(scan_path):
    scanned_files = []

    for root, folders, files in os.walk(scan_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            scanned_files.append(file_path)
            print("File found:", file_path)

    return scanned_files


def main():
    while True:
        show_menu()
        choice = get_menu_choice()

        if choice == 1:
            scan_path = get_scan_path()

            if scan_path is not None:
                print("\nScanning files...\n")
                scanned_files = scan_folder(scan_path)

                print("\nScan completed.")
                print("Total files scanned:", len(scanned_files))

        elif choice == 2:
            print("Exiting SecureDrive Scanner.")
            sys.exit()

        else:
            print("Invalid option. Please choose 1 or 2.")


if __name__ == "__main__":
    main()