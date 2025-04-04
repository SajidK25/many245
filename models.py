from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager
from itsdangerous import URLSafeTimedSerializer as Serializer
from datetime import datetime, timedelta
import uuid

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, name="uq_user_username")
    email = db.Column(db.String(120), unique=True, nullable=False, name="uq_user_email")
    phone_number = db.Column(db.String(15), unique=True, nullable=True, name="uq_user_phone_number")
    
    # Global notification settings
    notifications = db.Column(db.Boolean, default=False)
    email_enabled = db.Column(db.Boolean, default=False)  # Global email opt-in
    push_enabled = db.Column(db.Boolean, default=False)   # Global push opt-in
    sms_opt_in = db.Column(db.Boolean, default=False)     # Global SMS opt-in

    password = db.Column(db.String(60), nullable=False)
    max_logins = db.Column(db.Integer, default=1)
    active_tokens = db.relationship('LoginToken', backref='user', lazy=True)
    active_sessions = db.relationship('LoginSession', backref='user', lazy=True)
    role = db.Column(db.String(10), nullable=False, default='user')
    is_paid = db.Column(db.Boolean, default=False)
    payment_status = db.Column(db.String(20), default="Unpaid")
    payment_due_date = db.Column(db.Date, nullable=True)
    stripe_enabled = db.Column(db.Boolean, default=False)

    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    phone_verified = db.Column(db.Boolean, default=False)
    phone_verification_token = db.Column(db.String(100), nullable=True)

    amazon_relay_email = db.Column(db.String(120), unique=True, nullable=True, name="uq_user_amazon_relay_email")
    amazon_relay_password = db.Column(db.String(60), nullable=True)
    
    sms_fee_due = db.Column(db.Float, default=0.0)
    timezone = db.Column(db.String(50), default="UTC")

    # Password Management
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'email': self.email})
    
    def set_amazon_relay_password(self, password):
        self.amazon_relay_password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_amazon_relay_password(self, password):
        return bcrypt.check_password_hash(self.amazon_relay_password, password)
    
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            email = s.loads(token, max_age=1800)['email']
        except:
            return None
        return email

class UserNotification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    category = db.Column(db.String(50), nullable=False)

    sms_enabled = db.Column(db.Boolean, default=True)
    email_enabled = db.Column(db.Boolean, default=True)
    push_enabled = db.Column(db.Boolean, default=True)

    user = db.relationship('User', backref=db.backref('notifications_settings', lazy=True, cascade="all, delete"))

    __table_args__ = (
        db.CheckConstraint(
            "category IN ('Driver Late', 'Bob Tail', 'Ready to Pickup', 'Driver on time')",
            name="check_category_valid"
        ),
    )

    def to_dict(self):
        return {
            "category": self.category,
            "sms_enabled": self.sms_enabled,
            "email_enabled": self.email_enabled,
            "push_enabled": self.push_enabled
        }

class LoginToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class LoginSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)# Generate a password reset token

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=30.0)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_method = db.Column(db.String(20), nullable=False)  # 'cash', 'check', 'credit_card'
    status = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(50), unique=True, nullable=False)
    key_value = db.Column(db.String(255), nullable=False)

class VoipSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_username = db.Column(db.String(255), nullable=False)
    api_password = db.Column(db.String(255), nullable=False)
    api_did = db.Column(db.Integer, nullable=False)
    api_url = db.Column(db.String(255), nullable=False)
    sms_enabled = db.Column(db.Boolean, default=False)
    sms_fee = db.Column(db.Float, default=0.0)

class SMTPSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(255), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False)
    smtp_username = db.Column(db.String(255), nullable=False)
    smtp_password = db.Column(db.String(255), nullable=False)
    smtp_use_tls = db.Column(db.Boolean, default=True)
    smtp_use_ssl = db.Column(db.Boolean, default=True)
    default_sender = db.Column(db.String(255), nullable=True)

class HistoryLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)  # Track IP addresses
    user_agent = db.Column(db.String(255), nullable=True)  # Track device details
    user = db.relationship('User', backref=db.backref('history_logs', lazy=True))


class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('api_keys', lazy=True))

class RelayData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.String(120))
    load_id = db.Column(db.String(120))
    from_to = db.Column(db.String(120))
    driver_name = db.Column(db.String(120))
    loadType = db.Column(db.String(120))
    createTime = db.Column(db.String(120))
    status = db.Column(db.String(120))
    planned_arrival_stop1 = db.Column(db.String(120))
    actual_arrival_stop1 = db.Column(db.String(120))
    planned_Departure_stop1 = db.Column(db.String(120))
    actual_Departure_stop1 = db.Column(db.String(120))
    planned_arrival_stop2 = db.Column(db.String(120))
    actual_arrival_stop2 = db.Column(db.String(120))
    planned_Departure_stop2 = db.Column(db.String(120))
    actual_Departure_stop2 = db.Column(db.String(120))
    actual_stats = db.Column(db.String(120))
    arrival_departure_time = db.Column(db.String(120))
    tabname = db.Column(db.String(120))
