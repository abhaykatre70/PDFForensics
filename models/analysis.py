"""models/analysis.py — SQLAlchemy model for PDF analysis records."""
import datetime
from extensions import db


class Analysis(db.Model):
    __tablename__ = "analysis"

    id = db.Column(db.String(8), primary_key=True)          # e.g. 'A3F8B21C'
    sha256 = db.Column(db.String(64), index=True, nullable=False)
    md5 = db.Column(db.String(32))
    filename = db.Column(db.String(255))
    filesize = db.Column(db.Integer)
    trust_score = db.Column(db.Integer)
    classification = db.Column(db.String(32))
    analyzed_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    report_path = db.Column(db.String(512))                 # Absolute path to JSON report

    # Module detail JSON snapshots (stored as Text)
    module_metadata = db.Column(db.Text)
    module_signatures = db.Column(db.Text)
    module_structure = db.Column(db.Text)
    module_content = db.Column(db.Text)
    module_visual = db.Column(db.Text)

    findings = db.relationship("Finding", backref="analysis", lazy=True,
                               cascade="all, delete-orphan")

    def to_dict(self):
        import json
        return {
            "analysis_id": self.id,
            "filename": self.filename,
            "sha256": self.sha256,
            "md5": self.md5,
            "filesize": self.filesize,
            "trust_score": self.trust_score,
            "classification": self.classification,
            "analyzed_at": self.analyzed_at.isoformat() + "Z" if self.analyzed_at else None,
            "report_path": self.report_path,
            "findings": [f.to_dict() for f in self.findings],
        }

    def __repr__(self):
        return f"<Analysis {self.id} score={self.trust_score} file={self.filename}>"
