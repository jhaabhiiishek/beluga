import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150))
    scan_type = db.Column(db.String(50))
    result = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'scan_type': self.scan_type,
            'result': self.result,
            'timestamp': self.timestamp.isoformat()
        }
