from flask import request
from models import HistoryLog, db

def log_action(user_id, action):
    log = HistoryLog(
        user_id=user_id,
        action=action,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(log)
    db.session.commit()