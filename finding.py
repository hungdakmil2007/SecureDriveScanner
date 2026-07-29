#Author: Nguyen Hung Tran
#Final project - ITSC203

#Course requirement - Class:
#store the information for one security finding
class Finding:
    def __init__(
        self,
        file_path,
        finding_type,
        reason,
        risk_points,
        line_number=None,
        evidence=None
    ):
        self.file_path = file_path
        self.finding_type = finding_type
        self.reason = reason

        # Course requirement - Casting:
        # Convert risk_points to an integer before storing it
        self.risk_points = int(risk_points)

        # Phase 3 information for sensitive data findings
        self.line_number = line_number
        self.evidence = evidence