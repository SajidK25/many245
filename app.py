from flask import Flask, render_template, redirect, url_for, request, flash,session,current_app,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer as Serializer, SignatureExpired, BadTimeSignature,BadSignature
from flask_mail import Mail, Message
from models import db, User, LoginSession, Payment, SMTPSettings, VoipSettings, Config,HistoryLog,APIKey,RelayData,UserNotification
from api import api_bp
from utils import log_action
import os
import stripe
import uuid
import requests
import random
import pytz 
# from werkzeug.security import generate_password_hash
import smtplib

app = Flask(__name__)
# app.config.from_object("config.Config")
app.secret_key = 'your_secret_key_here'
# Use PostgreSQL in production, SQLite for local development
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'sample_secret_key_123456'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
mail = Mail(app)
app.register_blueprint(api_bp)


def get_smtp_settings():
    settings = SMTPSettings.query.first()
    if not settings:
        return None
    return {
        "MAIL_SERVER": settings.smtp_server,
        "MAIL_PORT": settings.smtp_port,
        "MAIL_USERNAME": settings.smtp_username,
        "MAIL_PASSWORD": settings.smtp_password,
        "MAIL_USE_TLS": settings.smtp_use_tls,
        "MAIL_USE_SSL": settings.smtp_use_ssl,
        "MAIL_DEFAULT_SENDER": settings.default_sender,
    }

def get_voipms_settings():
    settings = VoipSettings.query.first()
    if not settings:
        return None
    return {
        "API_USERNAME": settings.api_username,
        "API_PASSWORD": settings.api_password,
        "API_DID": settings.api_did,
        "API_URL": settings.api_url,
        "SMS_ENABLED": settings.sms_enabled,
        "SMS_FEE": settings.sms_fee,
    }

def get_extra_login_price():
    return float(get_config_value("EXTRA_LOGIN_PRICE") or 5.00)  # Default to $5

def set_extra_login_price(price):
    set_config_value("EXTRA_LOGIN_PRICE", str(price))

def get_sms_price():
    return round(float(get_config_value("SMS_PRICE") or 10.00),2)  # Default to $10

def set_sms_price(price):
    set_config_value("SMS_PRICE", str(price))

def get_config_value(key_name):
    config = Config.query.filter_by(key_name=key_name).first()
    return config.key_value if config else None

def set_config_value(key_name, key_value):
    config = Config.query.filter_by(key_name=key_name).first()
    if config:
        config.key_value = key_value
    else:
        config = Config(key_name=key_name, key_value=key_value)
        db.session.add(config)
    db.session.commit()

def send_email(to, subject, body):
    """Send an email using SMTP settings from the database."""
    
    smtp_settings = get_smtp_settings()
    if not smtp_settings:
        print("⚠️ SMTP settings not configured in the database.")
        return False

    # Apply settings dynamically
    current_app.config.update(
        MAIL_SERVER=smtp_settings["MAIL_SERVER"],
        MAIL_PORT=smtp_settings["MAIL_PORT"],
        MAIL_USERNAME=smtp_settings["MAIL_USERNAME"],
        MAIL_PASSWORD=smtp_settings["MAIL_PASSWORD"],
        MAIL_USE_TLS=smtp_settings["MAIL_USE_TLS"],
        MAIL_USE_SSL=smtp_settings["MAIL_USE_SSL"],
        MAIL_DEFAULT_SENDER=smtp_settings["MAIL_DEFAULT_SENDER"],
    )

    mail = Mail(current_app)
    msg = Message(subject=subject, sender=smtp_settings["MAIL_USERNAME"], recipients=[to])
    msg.body = body

    try:
        mail.send(msg)
        print(f"✅ Email sent successfully to {to}")
        return True
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

def send_sms(destination, message):
    """
    Send an SMS using VoIP.ms API.
    
    Parameters:
        did (str): Your VoIP.ms DID (number) to send the SMS from.
        destination (str): The destination phone number (international format, e.g., +1234567890).
        message (str): The text message to send.
    """
    voipms_settings = get_voipms_settings()
    if not voipms_settings:
        flash("❌ VoIP.ms settings not configured!", "error")
        return redirect(url_for("update_voipms_settings"))

    # Update Flask-Mail config
    current_app.config.update(
        API_USERNAME=voipms_settings["API_USERNAME"],
        API_PASSWORD=voipms_settings["API_PASSWORD"],
        API_DID=voipms_settings["API_DID"],
        API_URL=voipms_settings["API_URL"],
    )
    # API parameters
    params = {
        "api_username": voipms_settings["API_USERNAME"],
        "api_password": voipms_settings["API_PASSWORD"],
        "method": "sendSMS",
        "did": voipms_settings["API_DID"],  # Your VoIP.ms DID
        "dst": destination,  # Destination number
        "message": message,  # Message content
    }

    # Send request
    try:
        response = requests.get(voipms_settings["API_URL"], params=params)
        response_data = response.json()

        # Check API response
        if response_data.get("status") == "success":
            print("SMS sent successfully!")
        else:
            print(f"Error: {response_data.get('status')} - {response_data.get('message')}")

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
# def send_sms(phone_number, message):
    
#     payload = {
#         'api_username': app.config['VOIPMS_API_USERNAME'],
#         'api_password': app.config['VOIPMS_API_PASSWORD'],
#         'did': 'Your_VoIP_DID_Number',  # Replace with your DID number
#         'dst': phone_number,
#         'message': message
#     }
#     response = requests.post(app.config['VOIPMS_API_URL'], data=payload)
#     return response.json()

def notify_user(user, message):
    if user.notifications:
        if user.phone_number and user.sms_opt_in and user.phone_verified:
            send_sms(user.phone_number, message)
        if user.email and user.email_enabled and user.email_verified:
            msg = Message('Notification', recipients=[user.email], body=message)
            mail.send(msg)

def set_default_monthly_fee():
    if not Config.query.filter_by(key_name="MONTHLY_FEE").first():
        set_config_value("MONTHLY_FEE", "30.00")

def get_monthly_fee():
    fee = Config.query.filter_by(key_name="MONTHLY_FEE").first()
    return float(fee.key_value) if fee else 30.00  # Default value

def set_monthly_fee(new_fee):
    set_config_value("MONTHLY_FEE", str(new_fee))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/update_smtp_settings', methods=['GET', 'POST'])
@login_required
def update_smtp_settings():
    settings = SMTPSettings.query.first()  # Fetch the first SMTP settings record

    if request.method == 'POST':
        # If no settings exist, create a new entry
        if not settings:
            settings = SMTPSettings()

        # Update settings from form input
        settings.smtp_server = request.form.get('smtp_server')
        settings.smtp_port = request.form.get('smtp_port', type=int)
        settings.smtp_username = request.form.get('smtp_username')
        settings.smtp_password = request.form.get('smtp_password')
        settings.smtp_use_tls = bool(request.form.get('smtp_use_tls'))
        settings.smtp_use_ssl = bool(request.form.get('smtp_use_ssl'))
        settings.default_sender = request.form.get('default_sender')

        db.session.add(settings)
        db.session.commit()
        log_action(current_user.id, f"Updated SMTP settings")
        flash("SMTP settings updated successfully!", "success")
        return redirect(url_for('admin_dashboard'))  # Redirect admin to dashboard

    return render_template('update_smtp_settings.html', settings=settings)

@app.route('/test_smtp', methods=['GET','POST'])
@login_required
def test_smtp():
    """Send a test email using current SMTP settings."""
    test_email = request.form.get("test_email")
    if request.method == 'POST':
        # Load SMTP settings from database
        smtp_settings = get_smtp_settings()
        if not smtp_settings:
            flash("❌ SMTP settings not configured!", "error")
            return redirect(url_for("update_smtp_settings"))

        # Update Flask-Mail config
        current_app.config.update(
            MAIL_SERVER=smtp_settings["MAIL_SERVER"],
            MAIL_PORT=smtp_settings["MAIL_PORT"],
            MAIL_USERNAME=smtp_settings["MAIL_USERNAME"],
            MAIL_PASSWORD=smtp_settings["MAIL_PASSWORD"],
            MAIL_USE_TLS=smtp_settings["MAIL_USE_TLS"],
            MAIL_USE_SSL=smtp_settings["MAIL_USE_SSL"],
            MAIL_DEFAULT_SENDER=smtp_settings["MAIL_DEFAULT_SENDER"],
        )
        mail = Mail(current_app)
        try:
            msg = Message("Test Email", sender=smtp_settings["MAIL_USERNAME"], recipients=[test_email])
            msg.body = "This is a test email to verify SMTP settings."
            mail.send(msg)
            log_action(current_user.id, f"Sent test email to {test_email}")
            flash(f"✅ Test email sent to {test_email} successfully!", "success")
        except smtplib.SMTPException as e:
            flash(f"❌ Failed to send test email: {str(e)}", "error")

        return redirect(url_for("test_smtp"))
    return render_template('test_smtp.html')

@app.route('/test_sms', methods=['GET','POST'])
@login_required
def test_sms():
    """Send a test email using current SMTP settings."""
    dest_no = request.form.get("dest_no")
    test_sms = request.form.get("test_sms")
    if request.method == 'POST':

        try:
            send_sms(dest_no, test_sms)
            log_action(current_user.id, f"Sent test sms to {dest_no}")
            flash(f"✅ Test sms sent to {dest_no} successfully!", "success")
        except Exception as e:
            flash(f"❌ Failed to send test sms: {str(e)}", "error")

        return redirect(url_for("test_sms"))
    return render_template('test_voipms.html')

@app.route('/admin/update_voipms_settings', methods=['GET', 'POST'])
def update_voipms_settings():
    # Ensure only admin can access
    # if 'user_id' not in session or User.query.get(session['user_id']).role != 'admin':
    #     flash("Unauthorized access", "error")
    #     return redirect(url_for('admin_dashboard'))

    # Fetch existing settings from DB
    voip_settings = VoipSettings.query.first()

    if request.method == 'POST':
        api_username = request.form['api_username']
        api_password = request.form['api_password']
        api_did = request.form['api_did']
        api_url = request.form['api_url']
        sms_enabled = request.form.get('sms_enabled') == 'on'
        sms_fee = float(request.form['sms_fee']) if request.form['sms_fee'] else 0.0

        if not voip_settings:
            # Create new settings if none exist
            voip_settings = VoipSettings(api_username=api_username, api_password=api_password, api_did=api_did,api_url=api_url,sms_enabled=sms_enabled, sms_fee=sms_fee)
            db.session.add(voip_settings)
        else:
            # Update existing settings
            voip_settings.api_username = api_username
            voip_settings.api_password = api_password
            voip_settings.api_did = api_did
            voip_settings.api_url = api_url
            voip_settings.sms_enabled = sms_enabled
            voip_settings.sms_fee = sms_fee

        db.session.commit()
        log_action(current_user.id, f"Updated VoIP.ms settings")
        flash("VoIP.ms settings updated successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('voipms_settings.html', settings=voip_settings)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone_number = request.form['phone_number']
        notifications = 'notifications' in request.form  # Checkbox returns 'on' if checked
        
        # Check for duplicate username or email
        existing_user = User.query.filter((User.username == username) | (User.email == email) | (User.phone_number == phone_number)).first()

        if existing_user:
            flash('Username or email or phone number already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))
        
        try:
            user = User(username=username, email=email, phone_number=phone_number, notifications=notifications)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            log_action(user.id, "User registered")
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {e}', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/send_verification_email', methods=['GET','POST'])
@login_required
def send_verification_email():
    if current_user.email_verified:
        return jsonify({"message": "Email already verified."}), 400
    
    token = str(uuid.uuid4())
    current_user.verification_token = token
    db.session.commit()
    smtp_settings = get_smtp_settings()
    # Update Flask-Mail config
    current_app.config.update(
        MAIL_SERVER=smtp_settings["MAIL_SERVER"],
        MAIL_PORT=smtp_settings["MAIL_PORT"],
        MAIL_USERNAME=smtp_settings["MAIL_USERNAME"],
        MAIL_PASSWORD=smtp_settings["MAIL_PASSWORD"],
        MAIL_USE_TLS=smtp_settings["MAIL_USE_TLS"],
        MAIL_USE_SSL=smtp_settings["MAIL_USE_SSL"],
        MAIL_DEFAULT_SENDER=smtp_settings["MAIL_DEFAULT_SENDER"],
    )
        
    mail = Mail(current_app)
    verification_link = url_for('verify_email', token=token, _external=True)
    message = Message(
        'Email Verification',
        recipients=[current_user.email],
        body=f'Click the link to verify your email: {verification_link}'
    )
    mail.send(message)

    # flash('Verification email sent. Please check your inbox.', 'success')
    # return redirect(url_for('user_dashboard'))
    log_action(current_user.id, f"Sent verification email to {current_user.email}")
    return jsonify({"message": "Verification email sent! Check your inbox."})

@app.route('/verify_email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.email_verified = True
        user.verification_token = None
        db.session.commit()
        log_action(user.id, "Email verified")
        flash('Email successfully verified!', 'success')
    else:
        flash('Invalid or expired token.', 'error')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            reset_token = user.get_reset_token()
            reset_url = url_for('reset_password', token=reset_token, _external=True)

            # Send password reset email
            email_subject = "Password Reset Request"
            email_body = f"Click the link below to reset your password:\n{reset_url}"

            if send_email(user.email, email_subject, email_body):
                log_action(user.id, "Password reset email sent")
                flash("Check your email for password reset instructions.", "success")
            else:
                flash("Failed to send email. Contact support.", "error")

        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        # email = s.loads(token, max_age=3600)['email']
        # email = s.loads(token, salt="password-reset-salt", max_age=3600)  # 1-hour expiry
        email = User.verify_reset_token(token)
    except:
        flash("Invalid or expired token.", "error")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':
        new_password = request.form.get('password')
        user.set_password(new_password)
        db.session.commit()
        log_action(user.id, "Password reset")
        flash("Your password has been reset. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

@app.route('/send_otp', methods=['POST'])
@login_required
def send_otp():
    otp = random.randint(100000, 999999)
    current_user.phone_verification_token = str(otp)
    db.session.commit()

    message = f'Your OTP is: {otp}'
    response = send_sms(current_user.phone_number, message)

    try:
        send_sms(dest_no, test_sms)
        log_action(current_user.id, f"Sent test sms to {dest_no}")
        flash(f"✅ Test sms sent to {dest_no} successfully!", "success")
    except Exception as e:
            flash(f"❌ Failed to send test sms: {str(e)}", "error")

    return redirect(url_for('user_dashboard'))

@app.route('/verify_otp', methods=['POST'])
@login_required
def verify_otp():
    otp = request.form['otp']
    if current_user.phone_verification_token == otp:
        current_user.phone_verification_token = None
        current_user.phone_verified = True
        db.session.commit()
        log_action(current_user.id, "Phone number verified")
        flash('Phone number successfully verified!', 'success')
    else:
        flash('Invalid OTP.', 'error')

    return redirect(url_for('user_dashboard'))

def update_payment_status():
    users = User.query.all()
    today = datetime.utcnow().date()

    for user in users:
        if user.payment_due_date:
            days_remaining = (user.payment_due_date - today).days
            if days_remaining < 0:
                user.payment_status = "Expired"
                user.is_paid = False
            elif days_remaining >= 0 and user.is_paid:
                user.payment_status = "Paid"
            else:
                user.payment_status = "Unpaid"
        db.session.commit()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')  # Handle GET request properly

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            flash("Invalid username or password.", "error")
            return redirect(url_for('login'))

        # Admins have unlimited logins
        if user.role == "admin":
            login_user(user)
            log_action(user.id, "Admin logged in")
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_dashboard'))

        # Check active session count
        active_sessions = LoginSession.query.filter_by(user_id=user.id).count()
        if (active_sessions or 0) >= (user.max_logins or 1):
            flash("Maximum login limit reached. Upgrade to allow more sessions.", "error")
            return redirect(url_for('login'))

        # Generate a new session token
        new_token = str(uuid.uuid4())
        login_session = LoginSession(user_id=user.id, session_token=new_token)
        db.session.add(login_session)
        db.session.commit()

        session['login_token'] = new_token
        login_user(user)
        log_action(user.id, "User logged in")
        return redirect(url_for('user_dashboard'))

@app.route("/admin/update_login_price", methods=["POST"])
@login_required
def update_login_price():
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    new_price = request.form["extra_login_price"]
    try:
        set_extra_login_price(round(float(new_price),2))
        log_action(current_user.id, f"Updated extra login price to ${new_price}")
        flash("Extra login price updated successfully!", "success")
    except ValueError:
        flash("Invalid price entered.", "error")

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/update_sms_price", methods=["POST"])
@login_required
def update_sms_price():
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    new_price = request.form["sms_price"]
    try:
        set_sms_price(round(float(new_price),2))
        log_action(current_user.id, f"Updated sms price to ${new_price}")
        flash("Extra login price updated successfully!", "success")
    except ValueError:
        flash("Invalid price entered.", "error")

    return redirect(url_for("admin_dashboard"))

@app.route("/purchase_extra_login", methods=["GET", "POST"])
@login_required
def purchase_extra_login():
    if request.method == 'POST':
        try:
            extra_login_price = get_extra_login_price()

            # Create a Stripe checkout session
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'usd',
                        'product_data': {
                            'name': 'Extra Login Slot',
                        },
                        'unit_amount': int(extra_login_price * 100),  # Convert to cents
                    },
                    'quantity': 1,
                }],
                mode='payment',
                success_url=url_for('payment_success', _external=True),
                cancel_url=url_for('purchase_extra_login', _external=True),
            )
            return redirect(session.url, code=303)
        except Exception as e:
            flash(f"Error processing payment: {str(e)}", "error")
            return redirect(url_for('purchase_extra_login'))

    return render_template('purchase_extra_login.html')

@app.route('/payment_success')
@login_required
def payment_success():
    # Add an extra login slot for the user
    current_user.max_logins += 1
    db.session.commit()

    flash("Payment successful! Extra login slot added.", "success")
    return redirect(url_for('user_dashboard'))


@app.route('/admin/reset_sessions/<int:user_id>', methods=['POST'])
@login_required
def reset_user_sessions(user_id):
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    LoginSession.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    log_action(current_user.id, f"Admin reset sessions for user ID {user_id}")
    flash("All sessions for the user have been reset.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route('/admin/history_logs', methods=['GET'])
@login_required
def history_logs():
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for('login'))
    logs = HistoryLog.query.order_by(HistoryLog.timestamp.desc()).all()
    log_list = [
            {
                "id": log.id,
                "user": log.user.username,
                "role": log.user.role,
                "action": log.action,
                "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
            }
            for log in logs
        ]
    return render_template('admin_logs_history.html',logs=log_list)

@app.route('/logout')
@login_required
def logout():
    if current_user.role != "admin":
        # Delete all active sessions for the user
        LoginSession.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()

    session.pop('login_token', None)
    log_action(current_user.id, "User logged out")
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('login'))
    users = User.query.all()
    now = datetime.utcnow().date()
    return render_template('admin_dashboard.html', users=users,now=now,monthly_fee=get_monthly_fee(),extra_login_price=get_extra_login_price(),sms_fee=get_sms_price())

@app.route('/admin_settings', methods=['GET'])
@login_required
def admin_settings():
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('login'))
    return render_template('admin_settings.html',monthly_fee=get_monthly_fee(),extra_login_price=get_extra_login_price(),sms_fee=get_sms_price())

@app.route('/user_settings', methods=['GET'])
@login_required
def user_settings():
    now = datetime.utcnow().date()
    gmt_zones = [tz for tz in pytz.all_timezones if 'GMT' in tz]
    return render_template('user_settings.html',timezones=gmt_zones,now=now,monthly_fee=get_monthly_fee(),extra_login_price=get_extra_login_price(),sms_fee=get_sms_price())

@app.route('/update_timezone', methods=['POST'])
@login_required
def update_timezone():
    timezone = request.form.get("timezone")
    if timezone in pytz.all_timezones:
        current_user.timezone = timezone
        db.session.commit()
        log_action(current_user.id, f"Updated timezone to {timezone}")
        flash("Timezone updated successfully!", "success")
    return redirect(url_for('user_settings'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    search_filters = {
            'contract_id': request.args.get('contract_id'),
            'load_id': request.args.get('load_id'),
            'driver_name': request.args.get('driver_name'),
        }

    query = RelayData.query

    for field, value in search_filters.items():
        if value:
            query = query.filter(getattr(RelayData, field).ilike(f"%{value}%"))

    filtered_data = query.all()

    return render_template("user_dashboard.html", relay_data=filtered_data)

@app.route('/get_notification_settings')
@login_required
def get_notification_settings():
    print(f"Current User ID: {current_user.id}")  # Debugging
    settings = UserNotification.query.filter_by(user_id=current_user.id).all()
    print(f"User Settings Found: {settings}")  # Debugging
    return jsonify([setting.to_dict() for setting in settings])

@app.route('/update_notification_setting', methods=['POST'])
@login_required
def update_notification_setting():
    user_id = current_user.id  # Get the logged-in user ID
    data = request.get_json()

    category = data.get("category")
    notification_type = data.get("notification_type")
    enabled = data.get("enabled")

    # Check if the setting exists for this user
    setting = UserNotification.query.filter_by(user_id=user_id, category=category).first()

    # If not found, create a new record for this category
    if not setting:
        setting = UserNotification(
            user_id=user_id,
            category=category,
            sms_enabled=False,
            email_enabled=False,
            push_enabled=False
        )
        db.session.add(setting)
        db.session.commit()  # Commit here to ensure the new setting is saved

    # Update the specific notification type
    if notification_type == "sms":
        setting.sms_enabled = enabled
    elif notification_type == "email":
        setting.email_enabled = enabled
    elif notification_type == "push":
        setting.push_enabled = enabled

    db.session.commit()
    return jsonify({"success": True, "message": f"{notification_type} updated for {category}."})


# @app.route('/user/notifications/<int:user_id>', methods=['GET'])
# def get_notifications(user_id):
#     user = User.query.get(user_id)
#     if not user:
#         return jsonify({"error": "User not found"}), 404

#     global_settings = {
#         "email_enabled": user.email_enabled,
#         "push_enabled": user.push_enabled,
#         "sms_opt_in": user.sms_opt_in
#     }
    
#     category_settings = [n.to_dict() for n in user.notifications_settings]

#     return jsonify({"global_settings": global_settings, "category_settings": category_settings})

# @app.route('/user/notifications/global', methods=['POST'])
# def update_global_notifications():
#     data = request.json
#     user = User.query.get(data['user_id'])
    
#     if not user:
#         return jsonify({"error": "User not found"}), 404

#     user.email_enabled = data.get("email_enabled", user.email_enabled)
#     user.push_enabled = data.get("push_enabled", user.push_enabled)
#     user.sms_opt_in = data.get("sms_opt_in", user.sms_opt_in)

#     db.session.commit()
#     return jsonify({"message": "Global notification settings updated"})

@app.route('/user/notifications/category', methods=['POST'])
def update_category_notifications():
    data = request.json
    user = User.query.get(data['user_id'])
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    notification = UserNotification.query.filter_by(user_id=data['user_id'], category=data['category']).first()
    
    if not notification:
        return jsonify({"error": "Notification category not found"}), 404

    notification.sms_enabled = data.get("sms_enabled", notification.sms_enabled)
    notification.email_enabled = data.get("email_enabled", notification.email_enabled)
    notification.push_enabled = data.get("push_enabled", notification.push_enabled)

    db.session.commit()
    return jsonify({"message": "Category notification settings updated"})


@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone_number = request.form.get('phone_number')
        password = request.form['password']
        role = request.form['role']
        amazon_relay_email = request.form.get('amazon_relay_email')
        amazon_relay_password = request.form.get('amazon_relay_password')

        user.username = username
        user.email = email
        user.phone_number = phone_number
        user.role = role
        user.amazon_relay_email = amazon_relay_email
        if password:
            user.set_password(password)
        if amazon_relay_password:
            user.set_amazon_relay_password(amazon_relay_password)
        
        db.session.commit()
        log_action(current_user.id, f"Updated user {user.username}")
        flash(f"User {user.username}'s details have been updated.", 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)

@app.route('/admin/mark_paid/<int:user_id>', methods=['GET', 'POST'])
@login_required
def mark_paid(user_id):
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        payment_method = request.form['payment_method']
        amount = float(request.form.get('amount', 30.0))

        user.is_paid = True
        user.payment_due_date = datetime.utcnow() + timedelta(days=30)
        payment = Payment(user_id=user.id, amount=amount, payment_method=payment_method)
        db.session.add(payment)
        db.session.commit()
        log_action(current_user.id, f"Marked {user.username} as paid")
        flash(f"Payment of ${amount} recorded for {user.username}. Next payment due on {user.payment_due_date.strftime('%Y-%m-%d')}.", 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('mark_paid.html', user=user)

@app.route('/admin/add_payment/<int:user_id>', methods=['GET', 'POST'])
@login_required
def add_payment(user_id):
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        payment_method = request.form['payment_method']
        amount = float(request.form['amount'])

        payment = Payment(user_id=user.id, amount=amount, payment_method=payment_method)
        db.session.add(payment)
        db.session.commit()
        log_action(current_user.id, f"Added payment for {user.username}")
        flash(f"Payment of ${amount} added for {user.username} using {payment_method}.", 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_payment.html', user=user)

@app.route('/admin/view_payments')
@login_required
def view_payments():
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('dashboard'))

    payments = Payment.query.order_by(Payment.date.desc()).all()
    return render_template('payments.html', payments=payments)

@app.route("/admin/process_payment/<int:user_id>", methods=["POST"])
@login_required
def process_payment(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for('admin_dashboard'))

    payment_method = request.form.get('payment_method')
    amount = float(request.form.get('amount', 0))

    if payment_method in ['cash', 'check']:
        user.is_paid = True
        user.payment_due_date = datetime.utcnow() + timedelta(days=30)
        payment = Payment(user_id=user.id, amount=amount, payment_method=payment_method, status='success')
        db.session.add(payment)
        db.session.commit()
        log_action(current_user.id, f"Processed payment for {user.username}")
        flash("Payment recorded successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    elif payment_method == 'card':
        if not user.stripe_enabled:
            flash("Stripe payments are not enabled for this user.Please contact admin to enable Stripe.", "error")
            return redirect(url_for('admin_dashboard'))

        return redirect(url_for('stripe_payment', user_id=user.id, amount=amount))

    flash("Invalid payment method selected", "error")
    return redirect(url_for('admin_dashboard'))

# API Keys
@app.route('/admin/generate_api_key/<int:user_id>', methods=['GET','POST'])
@login_required
def generate_api_key(user_id):
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    new_key = APIKey(user_id=user_id)
    db.session.add(new_key)
    db.session.commit()
    log_action(current_user.id, f"Generated API key for user ID {user_id}")
    flash("New API key generated.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route('/admin/api_keys')
@login_required
def list_api_keys():
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    api_keys = APIKey.query.all()
    return render_template("api_keys.html", api_keys=api_keys)

# pay_subscription
@app.route('/user/pay_subscription/<int:user_id>', methods=['GET', 'POST'])
@login_required
def pay_subscription(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('payment_subscription.html', user=user, monthly_fee=get_monthly_fee())

@app.route("/user/process_subscription_payment/<int:user_id>", methods=["POST"])
@login_required
def process_subscription_payment(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_settings'))

    payment_method = request.form.get('payment_method')
    amount = round(float(request.form.get('amount', 0)))

    if payment_method in ['cash', 'check']:
        user.is_paid = True
        user.payment_due_date = datetime.utcnow() + timedelta(days=30)
        payment = Payment(user_id=user.id, amount=amount, payment_method=payment_method, status='success')
        db.session.add(payment)
        db.session.commit()
        log_action(current_user.id, f"Processed subscription payment for {user.username}")
        flash("Payment recorded successfully!", "success")
        return redirect(url_for('user_settings'))

    elif payment_method == 'card':
        if not user.stripe_enabled:
            flash("Stripe payments are not enabled for this user.Please contact admin to enable Stripe.", "error")
            return redirect(url_for('user_settings'))

        return redirect(url_for('user_stripe_payment_subscription', user_id=user.id, amount=amount))

    flash("Invalid payment method selected", "error")
    return redirect(url_for('user_settings'))

@app.route('/user_stripe_payment_subscription/<int:user_id>/<float:amount>')
def user_stripe_payment_subscription(user_id, amount):
    user = User.query.get(user_id)
    stripe_public_key = get_config_value("STRIPE_PUBLIC_KEY")
    if not user or not user.stripe_enabled:
        flash("User not found or Stripe not enabled", "error")
        return redirect(url_for('user_settings'))

    return render_template("user_stripe_payment_subscription.html", user_id=user_id, amount=amount, stripe_public_key=stripe_public_key)

@app.route('/charge_subscription/<int:user_id>', methods=['POST'])
def charge_subscription(user_id):
    stripe.api_key = get_config_value("STRIPE_SECRET_KEY")
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 400

    data = request.get_json()
    payment_method_id = data.get("payment_method_id")
    amount = float(data.get("amount", 0)) * 100  # Convert to cents

    try:
        # Create a payment intent with redirect disabled
        intent = stripe.PaymentIntent.create(
            amount=int(amount),
            currency="usd",
            payment_method=payment_method_id,
            confirm=True,
            automatic_payment_methods={
                "enabled": True,
                "allow_redirects": "never"  # Disable redirect-based methods
            }
        )

        # Save successful payment
        user.is_paid = True
        user.payment_due_date = datetime.utcnow() + timedelta(days=30)
        payment = Payment(user_id=user.id, amount=amount / 100, payment_method="card", status="success")
        db.session.add(payment)
        db.session.commit()

        return jsonify({"success": True, "message": "Payment successful!"})

    except stripe.error.StripeError as e:
        return jsonify({"success": False, "message": str(e)}), 400

# Pay SMS Notification
@app.route('/user/pay_sms_notification/<int:user_id>', methods=['GET', 'POST'])
@login_required
def pay_sms_notification(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('pay_sms_notification.html', user=user,sms_fee=get_sms_price())

@app.route("/user/process_sms_payment/<int:user_id>", methods=["POST"])
@login_required
def process_sms_payment(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_settings'))

    payment_method = request.form.get('payment_method')
    amount = float(request.form.get('amount', 0))

    if payment_method in ['cash', 'check']:
        user.notifications = True
        user.sms_opt_in = True
        payment = Payment(user_id=user.id, amount=amount, payment_method=payment_method, status='success')
        db.session.add(payment)
        db.session.commit()
        log_action(current_user.id, f"Processed SMS payment for {user.username}")
        flash("Payment recorded successfully!", "success")
        return redirect(url_for('user_settings'))

    elif payment_method == 'card':
        if not user.stripe_enabled:
            flash("Stripe payments are not enabled for this user.Please contact admin to enable Stripe.", "error")
            return redirect(url_for('user_settings'))

        return redirect(url_for('user_stripe_sms_payment', user_id=user.id, amount=amount))

    flash("Invalid payment method selected", "error")
    return redirect(url_for('user_settings'))

@app.route('/user_stripe_sms_payment/<int:user_id>/<float:amount>')
def user_stripe_sms_payment(user_id, amount):
    user = User.query.get(user_id)
    stripe_public_key = get_config_value("STRIPE_PUBLIC_KEY")
    if not user or not user.stripe_enabled:
        flash("User not found or Stripe not enabled", "error")
        return redirect(url_for('user_settings'))

    return render_template("user_stripe_sms_payment.html", user_id=user_id, amount=amount, stripe_public_key=stripe_public_key)

@app.route('/charge_sms/<int:user_id>', methods=['POST'])
def charge_sms(user_id):
    stripe.api_key = get_config_value("STRIPE_SECRET_KEY")
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 400

    data = request.get_json()
    payment_method_id = data.get("payment_method_id")
    amount = float(data.get("amount", 0)) * 100  # Convert to cents

    try:
        # Create a payment intent with redirect disabled
        intent = stripe.PaymentIntent.create(
            amount=int(amount),
            currency="usd",
            payment_method=payment_method_id,
            confirm=True,
            automatic_payment_methods={
                "enabled": True,
                "allow_redirects": "never"  # Disable redirect-based methods
            }
        )

        # Save successful payment
        user.notifications = True
        user.sms_opt_in = True
        payment = Payment(user_id=user.id, amount=amount / 100, payment_method="card", status="success")
        db.session.add(payment)
        db.session.commit()

        return jsonify({"success": True, "message": "Payment successful!"})

    except stripe.error.StripeError as e:
        return jsonify({"success": False, "message": str(e)}), 400

# Payment extra login
@app.route('/user/pay_extra_login/<int:user_id>', methods=['GET', 'POST'])
@login_required
def pay_extra_login(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('pay_extra_login.html', user=user,extra_login_price=get_extra_login_price())

@app.route("/user/process_extra_login_payment/<int:user_id>", methods=["POST"])
@login_required
def process_extra_login_payment(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_settings'))

    payment_method = request.form.get('payment_method')
    amount = float(request.form.get('amount', 0))

    if payment_method in ['cash', 'check']:
        user.max_logins += 1
        payment = Payment(user_id=user.id, amount=amount, payment_method=payment_method, status='success')
        db.session.add(payment)
        db.session.commit()
        log_action(current_user.id, f"Processed extra login payment for {user.username}")
        flash("Payment recorded successfully!", "success")
        return redirect(url_for('user_settings'))

    elif payment_method == 'card':
        if not user.stripe_enabled:
            flash("Stripe payments are not enabled for this user.Please contact admin to enable Stripe.", "error")
            return redirect(url_for('user_dashboard'))

        return redirect(url_for('user_stripe_extra_login_payment', user_id=user.id, amount=amount))

    flash("Invalid payment method selected", "error")
    return redirect(url_for('user_settings'))

@app.route('/user_stripe_extra_login_payment/<int:user_id>/<float:amount>')
def user_stripe_extra_login_payment(user_id, amount):
    user = User.query.get(user_id)
    stripe_public_key = get_config_value("STRIPE_PUBLIC_KEY")
    if not user or not user.stripe_enabled:
        flash("User not found or Stripe not enabled", "error")
        return redirect(url_for('user_dashboard'))

    return render_template("user_stripe_extra_login_payment.html", user_id=user_id, amount=amount, stripe_public_key=stripe_public_key)

@app.route('/charge_extra_login/<int:user_id>', methods=['POST'])
def charge_extra_login(user_id):
    stripe.api_key = get_config_value("STRIPE_SECRET_KEY")
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 400

    data = request.get_json()
    payment_method_id = data.get("payment_method_id")
    amount = float(data.get("amount", 0)) * 100  # Convert to cents

    try:
        # Create a payment intent with redirect disabled
        intent = stripe.PaymentIntent.create(
            amount=int(amount),
            currency="usd",
            payment_method=payment_method_id,
            confirm=True,
            automatic_payment_methods={
                "enabled": True,
                "allow_redirects": "never"  # Disable redirect-based methods
            }
        )

        # Save successful payment
        user.max_logins += 1
        payment = Payment(user_id=user.id, amount=amount / 100, payment_method="card", status="success")
        db.session.add(payment)
        db.session.commit()

        return jsonify({"success": True, "message": "Payment successful!"})

    except stripe.error.StripeError as e:
        return jsonify({"success": False, "message": str(e)}), 400

@app.route('/stripe_payment/<int:user_id>/<float:amount>')
def stripe_payment(user_id, amount):
    user = User.query.get(user_id)
    stripe_public_key = get_config_value("STRIPE_PUBLIC_KEY")
    if not user or not user.stripe_enabled:
        flash("User not found or Stripe not enabled", "error")
        return redirect(url_for('admin_dashboard'))

    return render_template("stripe_payment.html", user_id=user_id, amount=amount, stripe_public_key=stripe_public_key)



@app.route('/charge/<int:user_id>', methods=['POST'])
def charge(user_id):
    stripe.api_key = get_config_value("STRIPE_SECRET_KEY")
    user = User.query.get(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 400

    data = request.get_json()
    payment_method_id = data.get("payment_method_id")
    amount = float(data.get("amount", 0)) * 100  # Convert to cents

    try:
        # Create a payment intent with redirect disabled
        intent = stripe.PaymentIntent.create(
            amount=int(amount),
            currency="usd",
            payment_method=payment_method_id,
            confirm=True,
            automatic_payment_methods={
                "enabled": True,
                "allow_redirects": "never"  # Disable redirect-based methods
            }
        )

        # Save successful payment
        user.is_paid = True
        user.payment_due_date = datetime.utcnow() + timedelta(days=30)
        payment = Payment(user_id=user.id, amount=amount / 100, payment_method="card", status="success")
        db.session.add(payment)
        db.session.commit()

        return jsonify({"success": True, "message": "Payment successful!"})

    except stripe.error.StripeError as e:
        return jsonify({"success": False, "message": str(e)}), 400

@app.route("/admin/update_stripe_keys", methods=["GET", "POST"])
@login_required
def update_stripe_keys():
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        stripe_public_key = request.form["stripe_public_key"]
        stripe_secret_key = request.form["stripe_secret_key"]

        set_config_value("STRIPE_PUBLIC_KEY", stripe_public_key)
        set_config_value("STRIPE_SECRET_KEY", stripe_secret_key)
        log_action(current_user.id, "Updated Stripe API keys")
        flash("Stripe API keys updated successfully!", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("update_stripe_keys.html",
                           stripe_public_key=get_config_value("STRIPE_PUBLIC_KEY"),
                           stripe_secret_key=get_config_value("STRIPE_SECRET_KEY"))


@app.route("/user/payment", methods=["GET", "POST"])
@login_required
def user_payment():
    if not current_user.stripe_enabled:
        flash("Stripe payments are not enabled for your account.", "error")
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        amount = float(request.form["amount"]) * 100  # Convert to cents

        try:
            charge = stripe.Charge.create(
                amount=int(amount),
                currency="usd",
                description=f"Payment for {current_user.username}",
                source=request.form["stripeToken"],
            )
            current_user.is_paid = True
            current_user.payment_due_date = datetime.utcnow().date() + timedelta(days=30)
            db.session.commit()
            log_action(current_user.id, "Payment processed")
            flash("Payment successful!", "success")
            return redirect(url_for("user_dashboard"))
        except stripe.error.StripeError as e:
            flash(f"Payment failed: {e.user_message}", "error")

    return render_template("user_payment.html", stripe_public_key=app.config["STRIPE_PUBLIC_KEY"])

@app.route("/admin/toggle_stripe/<int:user_id>", methods=["POST"])
@login_required
def toggle_stripe(user_id):
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    user = User.query.get_or_404(user_id)
    user.stripe_enabled = not user.stripe_enabled
    db.session.commit()
    log_action(current_user.id, f"{'Enabled' if user.stripe_enabled else 'Disabled'} Stripe payments for {user.username}")
    flash(f"Stripe payments {'enabled' if user.stripe_enabled else 'disabled'} for {user.username}.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/toggle_email/<int:user_id>", methods=["POST"])
@login_required
def toggle_email(user_id):
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    user = User.query.get_or_404(user_id)
    user.email_enabled = not user.email_enabled
    db.session.commit()
    log_action(current_user.id, f"{'Enabled' if user.email_enabled else 'Disabled'} email notifications for {user.username}")
    flash(f"Email notification {'enabled' if user.email_enabled else 'disabled'} for {user.username}.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/toggle_push/<int:user_id>", methods=["POST"])
@login_required
def toggle_push(user_id):
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    user = User.query.get_or_404(user_id)
    user.push_enabled = not user.push_enabled
    db.session.commit()
    log_action(current_user.id, f"{'Enabled' if user.push_enabled else 'Disabled'} push notifications for {user.username}")
    flash(f"Push notification {'enabled' if user.push_enabled else 'disabled'} for {user.username}.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/toggle_sms_opt_in/<int:user_id>", methods=["POST"])
@login_required
def toggle_sms_opt_in(user_id):
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    user = User.query.get_or_404(user_id)
    
    today = datetime.utcnow().date()
    days_in_month = 30  # Assuming a 30-day month for simplicity
    days_remaining = max((user.payment_due_date - today).days, 0)

    if not user.sms_opt_in:
        # Calculate prorated fee
        prorated_fee = round((days_remaining / days_in_month) * get_sms_price(), 2) if days_remaining > 0 else get_sms_price()
        user.sms_fee_due = prorated_fee
        user.sms_opt_in = True
        user.notifications= True
        log_action(current_user.id, f"Enabled SMS alerts for {user.username}")
        flash(f"SMS alerts enabled. Prorated fee: ${prorated_fee}. Please proceed to payment.", "success")
    else:
        user.sms_opt_in = False
        user.notifications= False
        log_action(current_user.id, f"Disabled SMS alerts for {user.username}")
        flash("SMS alerts disabled.", "success")

    db.session.commit()
    return redirect(url_for("admin_dashboard"))

@app.route("/payment", methods=["GET", "POST"])
@login_required
def payment():
    base_amount = get_monthly_fee()  # Use the dynamic fee
    sms_fee = current_user.sms_fee_due if current_user.sms_opt_in else 0.00
    total_amount = base_amount + sms_fee

    if request.method == "POST":
        amount_in_cents = int(total_amount * 100)

        try:
            charge = stripe.Charge.create(
                amount=amount_in_cents,
                currency="usd",
                description=f"Payment for {current_user.username}",
                source=request.form["stripeToken"],
            )
            current_user.is_paid = True
            current_user.payment_due_date = datetime.utcnow().date() + timedelta(days=30)
            current_user.sms_fee_due = 0.0
            db.session.commit()
            log_action(current_user.id, "Payment processed")
            flash("Payment successful!", "success")
            return redirect(url_for("user_dashboard"))
        except stripe.error.StripeError as e:
            flash(f"Payment failed: {e.user_message}", "error")

    return render_template("payment.html", total_amount=total_amount, stripe_public_key=get_config_value("STRIPE_PUBLIC_KEY"))

@app.route("/admin/update_monthly_fee", methods=["POST"])
@login_required
def update_monthly_fee():
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    new_fee = request.form["monthly_fee"]
    try:
        set_monthly_fee(round(float(new_fee),2))
        log_action(current_user.id, f"Updated monthly fee to ${new_fee}")
        flash("Monthly fee updated successfully!", "success")
    except ValueError:
        flash("Invalid amount. Please enter a valid number.", "error")

    return redirect(url_for("admin_dashboard"))


@app.route('/update_amazon_relay', methods=['POST'])
@login_required
def update_amazon_relay():
    amazon_relay_email = request.form.get('amazon_relay_email')
    amazon_relay_password = request.form.get('amazon_relay_password')
    
    if amazon_relay_email and amazon_relay_password:
        current_user.amazon_relay_email = amazon_relay_email
        current_user.set_amazon_relay_password(amazon_relay_password)  # Encrypt password
        db.session.commit()
        log_action(current_user.id, "Updated Amazon Relay credentials")
        flash('Amazon Relay credentials updated successfully.', 'success')
    else:
        flash('Both fields are required.', 'error')
    
    return redirect(url_for('user_settings'))

@app.route('/relay_data', methods=['GET', 'POST'])
def relay_data():
    search_filters = {
        'contract_id': request.args.get('contract_id'),
        'load_id': request.args.get('load_id'),
        'driver_name': request.args.get('driver_name'),
    }

    query = RelayData.query

    for field, value in search_filters.items():
        if value:
            query = query.filter(getattr(RelayData, field).ilike(f"%{value}%"))

    filtered_data = query.all()

    return render_template("relay_data.html", relay_data=filtered_data)

@app.route('/send_alert', methods=['POST'])
def send_alert():
    load_id = request.form.get('load_id')
    alert_type = request.form.get('alert_type')

    # Fetch load data
    load_data = RelayData.query.filter_by(load_id=load_id).first()

    # Handle Alerts
    if alert_type == 'sms':
        send_sms(f"ALERT: Issue with Load {load_id} - {load_data.status}")
    elif alert_type == 'email':
        send_email("Load Alert", f"ALERT: Issue with Load {load_id} - {load_data.status}")
    elif alert_type == 'push':
        send_push_notification(f"ALERT: Issue with Load {load_id} - {load_data.status}")

    flash(f"{alert_type.upper()} Alert Sent for Load {load_id}", "success")
    return redirect(url_for('relay_data'))

# def send_sms(message):
#     # Example: Integrate with Twilio or VoIP.ms
#     print("Sending SMS:", message)

def send_email(subject, body):
    # Example: Use Flask-Mail or SMTP here
    print("Sending Email:", subject, body)

def send_push_notification(message):
    # Example: Push notification logic here
    print("Sending Push Notification:", message)


@app.cli.command('initdb')
def initdb():
    """Initialize the database."""
    with app.app_context():
        try:
            db.create_all()
            print("Database initialized. Tables created:")
            for table_name in db.metadata.tables.keys():
                print(f"- {table_name}")
        except Exception as e:
            print(f"Error initializing the database: {e}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)