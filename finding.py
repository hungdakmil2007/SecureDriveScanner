# Store the information for one security finding
class Finding:
    def __init__(self, file_path, finding_type, reason, risk_points):
        self.file_path = file_path
        self.finding_type = finding_type
        self.reason = reason
        self.risk_points = int(risk_points)