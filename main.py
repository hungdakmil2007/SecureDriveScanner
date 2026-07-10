import os
import sys


#display the main menu
def show_menu():
    print("\nSecureDrive Scanner")
    print("-------------------")
    print("1. Scan USB or folder")
    print("2. Exit")


#get the menu choice and convert it to an integer
def get_menu_choice():
    try:
        choice = int(input("Choose an option: "))
        return choice
    except ValueError:
        return 0


#ask the user for a path and check if it exists
def get_scan_path():
    scan_path = input("Enter USB or folder path: ").strip()

    if os.path.exists(scan_path):
        print("Path found:", scan_path)
        return scan_path

    print("Invalid path.")
    return None


def main():
    while True:
        show_menu()
        choice = get_menu_choice()

        if choice == 1:
            scan_path = get_scan_path()

            if scan_path is not None:
                print("The folder is ready to scan.")

        elif choice == 2:
            print("Exiting SecureDrive Scanner.")
            sys.exit()

        else:
            print("Invalid option. Please choose 1 or 2.")


if __name__ == "__main__":
    main()