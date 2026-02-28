"""models/finding.py — SQLAlchemy model for individual forensic findings."""
from extensions import db

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Finding(db.Model):
    __tablename__ = "finding"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    analysis_id = db.Column(db.String(8), db.ForeignKey("analysis.id"), nullable=False)
    module = db.Column(db.String(32))    # 'Metadata' | 'Signatures' | 'Structure' | 'Content' | 'Visual'
    severity = db.Column(db.String(16))  # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
    title = db.Column(db.String(255))
    detail = db.Column(db.Text)
    evidence = db.Column(db.Text)        # Raw evidence string or JSON snippet

    def to_dict(self):
        return {
            "id": self.id,
            "module": self.module,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }

    def __repr__(self):
        return f"<Finding [{self.severity}] {self.title}>"
