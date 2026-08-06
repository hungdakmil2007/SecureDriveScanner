#Author: Nguyen Hung Tran
#Final project - ITSC203

import os
from datetime import datetime

# Course requirement - Function:
#give a recommendation based on the finding type
def get_recommendation(finding_type):
    if finding_type == "Risky file type":
        return "Do not open this file unless the source is trusted."

    elif finding_type == "Double extension":
        return "Check the real file type before opening this file."

    elif finding_type == "Autorun file":
        return "Review this file before using the USB drive."

    elif finding_type == "Macro-enabled Office file":
        return "Do not enable macros unless the document is trusted."

    elif finding_type == "Possible email address":
        return "Review whether this email address should be stored or shared."

    elif finding_type == "Possible phone number":
        return "Review whether this phone number should be stored or shared."

    elif finding_type == "Possible password value":
        return "Remove plain-text passwords and store them securely."

    elif finding_type == "Possible API key":
        return "Remove the API key and store it in an environment variable."

    elif finding_type == "Possible token":
        return "Remove the token and store it in a secure location."

    elif finding_type == "Possible private key":
        return "Remove the private key and store it in a secure location."

    elif finding_type == "Possible SIN-like number":
        return "Review and remove this personal number before sharing the file."

    elif finding_type == "Possible credit-card-like number":
        return "Review and remove this payment information before sharing the file."
    return "Review this file before opening it."

# Course requirement - Function and File handling:
#create and save the text report
def generate_report(
    scan_path,
    scanned_files,
    findings,
    skipped_items,
    hash_results,
    risk_score,
    risk_level
):
    report_folder = "reports"
    # Course requirement - OS module:
    #create the reports folder if it does not exist
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)

    current_time = datetime.now()
    file_time = current_time.strftime("%Y%m%d_%H%M%S")

    report_name = "scan_report_" + file_time + ".txt"
    #use os.path.join() so the path works on Windows and Linux
    report_path = os.path.join(report_folder, report_name)

    # File handling requirement: save the scan result in a text file
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("SecureDrive Scanner Report\n")
        report.write("==========================\n\n")

        report.write("Scan path: " + scan_path + "\n")
        report.write(
            "Scan time: "
            + current_time.strftime("%Y-%m-%d %H:%M:%S")
            + "\n"
        )
        # Course requirement - Casting, int to string
        report.write(
            "Total files scanned: "
            + str(len(scanned_files))
            + "\n"
        )

        report.write(
            "Total findings: "
            + str(len(findings))
            + "\n"
        )
        report.write(
            "Skipped items: "
            + str(len(skipped_items))
            + "\n"
        )

        report.write(
            "Files hashed: "
            + str(len(hash_results))
            + "\n"
        )

        report.write("Risk score: " + str(risk_score) + "\n")
        report.write("Risk level: " + risk_level + "\n")

        report.write("\nFindings\n")
        report.write("--------\n")

        if len(findings) == 0:
            report.write("No risky file indicators were found.\n")

        else:
            finding_number = 1

            for finding in findings:
                report.write(
                    "\nFinding "
                    + str(finding_number)
                    + "\n"
                )

                report.write(
                    "File: "
                    + finding.file_path
                    + "\n"
                )

                report.write(
                    "Type: "
                    + finding.finding_type
                    + "\n"
                )

                report.write(
                    "Reason: "
                    + finding.reason
                    + "\n"
                )

                # Phase 3:
                # Save the line number and masked evidence when available
                if finding.line_number is not None:
                    report.write(
                        "Line number: "
                        + str(finding.line_number)
                        + "\n"
                    )

                if finding.evidence is not None:
                    report.write(
                        "Masked evidence: "
                        + finding.evidence
                        + "\n"
                    )

                report.write(
                    "Risk points: "
                    + str(finding.risk_points)
                    + "\n"
                )

                recommendation = get_recommendation(
                    finding.finding_type
                )

                report.write(
                    "Recommendation: "
                    + recommendation
                    + "\n"
                )

                finding_number += 1

        # Phase 3:
        # Save SHA256 results for suspicious files
        report.write("\nSHA256 Hash Results\n")
        report.write("-------------------\n")

        if len(hash_results) == 0:
            report.write("No suspicious files were hashed.\n")

        else:
            hash_number = 1

            for hash_result in hash_results:
                report.write(
                    "\nHash Result "
                    + str(hash_number)
                    + "\n"
                )

                report.write(
                    "File: "
                    + hash_result["file_path"]
                    + "\n"
                )

                report.write(
                    "SHA256: "
                    + hash_result["sha256"]
                    + "\n"
                )

                hash_number += 1
                
        report.write("\nSkipped Items\n")
        report.write("-------------\n")

        if len(skipped_items) == 0:
            report.write("No items were skipped.\n")

        else:
            for item in skipped_items:
                report.write("- " + item + "\n")

        report.write("\nFinal Recommendation\n")
        report.write("--------------------\n")

        if risk_level == "High":
            report.write(
                "Do not open the risky files until they are reviewed.\n"
            )

        elif risk_level == "Medium":
            report.write(
                "Review the findings before using or sharing the files.\n"
            )

        elif risk_level == "Low":
            report.write(
                "Use caution and review the reported files.\n"
            )

        else:
            report.write(
                "No risky file indicators were found during this scan.\n"
            )

    return report_path