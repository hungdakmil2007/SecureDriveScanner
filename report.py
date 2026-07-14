import os
from datetime import datetime


# Give a recommendation based on the finding type
def get_recommendation(finding_type):
    if finding_type == "Risky file type":
        return "Do not open this file unless the source is trusted."

    elif finding_type == "Double extension":
        return "Check the real file type before opening this file."

    elif finding_type == "Autorun file":
        return "Review this file before using the USB drive."

    elif finding_type == "Macro-enabled Office file":
        return "Do not enable macros unless the document is trusted."

    return "Review this file before opening it."


# Create and save the text report
def generate_report(
    scan_path,
    scanned_files,
    findings,
    skipped_items,
    risk_score,
    risk_level
):
    report_folder = "reports"

    # Create the reports folder if it does not exist
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)

    current_time = datetime.now()
    file_time = current_time.strftime("%Y%m%d_%H%M%S")

    report_name = "scan_report_" + file_time + ".txt"
    report_path = os.path.join(report_folder, report_name)

    # File handling requirement: save the scan results
    with open(report_path, "w", encoding="utf-8") as report:
        report.write("SecureDrive Scanner Report\n")
        report.write("==========================\n\n")

        report.write("Scan path: " + scan_path + "\n")
        report.write(
            "Scan time: "
            + current_time.strftime("%Y-%m-%d %H:%M:%S")
            + "\n"
        )

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