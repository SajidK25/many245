from flask import Flask, render_template, redirect, url_for, request, flash,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime, timedelta
import os
import stripe
from flask_mail import Mail, Message
import uuid
import requests
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
mail = Mail(app)
# Use PostgreSQL in production, SQLite for local development
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = 'sample_secret_key_123456'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
# SMTP Server Config
app.config['MAIL_SERVER'] = 'smtp.example.com'  # Replace with your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'  # Your SMTP username
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Your SMTP password
app.config['MAIL_DEFAULT_SENDER'] = 'your_email@example.com'

# VoIP.ms Config
app.config['VOIPMS_API_URL'] = 'https://voip.ms/api/v1/rest.php'
app.config['VOIPMS_API_USERNAME'] = 'your_voipms_username'
app.config['VOIPMS_API_PASSWORD'] = 'your_voipms_password'

# Stripe Config
app.config["STRIPE_SECRET_KEY"] = "your_secret_key"
app.config["STRIPE_PUBLIC_KEY"] = "your_public_key"

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, name="uq_user_username")  # Named unique constraint
    email = db.Column(db.String(120), unique=True, nullable=False, name="uq_user_email")  # Named unique constraint
    phone_number = db.Column(db.String(15), unique=True, nullable=True, name="uq_user_phone_number")  # Named unique constraint
    notifications = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(60), nullable=False)
    max_logins = db.Column(db.Integer, default=1)  # Default to 1 active login
    active_tokens = db.relationship('LoginToken', backref='user', lazy=True)
    role = db.Column(db.String(10), nullable=False, default='user')
    is_paid = db.Column(db.Boolean, default=False)
    payment_status = db.Column(db.String(20), default="Unpaid")
    payment_due_date = db.Column(db.Date, nullable=True)
    stripe_enabled = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    amazon_relay_email = db.Column(db.String(120), unique=True, nullable=True, name="uq_user_amazon_relay_email")  # Named unique constraint
    amazon_relay_password = db.Column(db.String(60), nullable=True)
    sms_opt_in = db.Column(db.Boolean, default=False)  # Track if SMS alerts are enabled
    sms_fee_due = db.Column(db.Float, default=0.0)  # Track the prorated amount
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def set_amazon_relay_password(self, password):
        self.amazon_relay_password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_amazon_relay_password(self, password):
        return bcrypt.check_password_hash(self.amazon_relay_password, password)

class LoginToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=30.0)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_method = db.Column(db.String(20), nullable=False)  # 'cash', 'check', 'credit_card'

class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(50), unique=True, nullable=False)
    key_value = db.Column(db.String(255), nullable=False)

class VoipSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_username = db.Column(db.String(255), nullable=False)
    api_password = db.Column(db.String(255), nullable=False)
    sms_enabled = db.Column(db.Boolean, default=False)
    sms_fee = db.Column(db.Float, default=0.0)

@app.before_request
def clean_expired_sessions():
    session_lifetime = timedelta(hours=24)  # Auto-expire after 24 hours
    expiry_time = datetime.utcnow() - session_lifetime
    LoginToken.query.filter(LoginToken.created_at < expiry_time).delete()
    db.session.commit()

def get_extra_login_price():
    return float(get_config_value("EXTRA_LOGIN_PRICE") or 5.00)  # Default to $5

def set_extra_login_price(price):
    set_config_value("EXTRA_LOGIN_PRICE", str(price))

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

def send_sms(phone_number, message):
    payload = {
        'api_username': app.config['VOIPMS_API_USERNAME'],
        'api_password': app.config['VOIPMS_API_PASSWORD'],
        'did': 'Your_VoIP_DID_Number',  # Replace with your DID number
        'dst': phone_number,
        'message': message
    }
    response = requests.post(app.config['VOIPMS_API_URL'], data=payload)
    return response.json()

def notify_user(user, message):
    if user.notifications:
        if user.phone_number:
            send_sms(user.phone_number, message)
        if user.email:
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
# @app.route('/forgot_password', methods=['GET', 'POST'])
# def forgot_password():
#     return render_template('forgot_password.html')
@app.route('/update_smtp_settings', methods=['GET', 'POST'])
def update_smtp_settings():
    return render_template('update_smtp_settings.html')

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
        sms_enabled = request.form.get('sms_enabled') == 'on'
        sms_fee = float(request.form['sms_fee']) if request.form['sms_fee'] else 0.0

        if not voip_settings:
            # Create new settings if none exist
            voip_settings = VoipSettings(api_username=api_username, api_password=api_password, sms_enabled=sms_enabled, sms_fee=sms_fee)
            db.session.add(voip_settings)
        else:
            # Update existing settings
            voip_settings.api_username = api_username
            voip_settings.api_password = api_password
            voip_settings.sms_enabled = sms_enabled
            voip_settings.sms_fee = sms_fee

        db.session.commit()
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
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {e}', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/send_verification_email', methods=['POST'])
@login_required
def send_verification_email():
    token = str(uuid.uuid4())
    current_user.verification_token = token
    db.session.commit()

    verification_link = url_for('verify_email', token=token, _external=True)
    message = Message(
        'Email Verification',
        recipients=[current_user.email],
        body=f'Click the link to verify your email: {verification_link}'
    )
    mail.send(message)

    flash('Verification email sent. Please check your inbox.', 'success')
    return redirect(url_for('user_dashboard'))

@app.route('/verify_email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.email_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Email successfully verified!', 'success')
    else:
        flash('Invalid or expired token.', 'error')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = str(uuid.uuid4())
            user.verification_token = token
            db.session.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            message = Message(
                'Password Reset Request',
                recipients=[email],
                body=f'Click the link to reset your password: {reset_link}'
            )
            mail.send(message)

            flash('Password reset email sent. Please check your inbox.', 'success')
        else:
            flash('No account found with that email.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        user.set_password(new_password)
        user.verification_token = None
        db.session.commit()
        flash('Password updated successfully.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/send_otp', methods=['POST'])
@login_required
def send_otp():
    otp = random.randint(100000, 999999)
    current_user.verification_token = str(otp)
    db.session.commit()

    message = f'Your OTP is: {otp}'
    response = send_sms(current_user.phone_number, message)

    if response.get('status') == 'success':
        flash('OTP sent to your phone.', 'success')
    else:
        flash('Failed to send OTP. Please try again.', 'error')

    return redirect(url_for('user_dashboard'))

@app.route('/verify_otp', methods=['POST'])
@login_required
def verify_otp():
    otp = request.form['otp']
    if current_user.verification_token == otp:
        current_user.verification_token = None
        db.session.commit()
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
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Admins have unlimited logins
            if user.role == "admin":
                login_user(user)
                flash("Admin login successful!", "success")
                return redirect(url_for('admin_dashboard'))

            # Regular users must adhere to the login limit
            active_sessions = LoginToken.query.filter_by(user_id=user.id).count()
            if (active_sessions or 0) >= (user.max_logins or 1):
                flash("Maximum login limit reached. Upgrade to allow more sessions.", "error")
                return redirect(url_for('login'))

            # Generate new login token
            new_token = str(uuid.uuid4())
            session['login_token'] = new_token  # Store token in session
            login_token = LoginToken(user_id=user.id, token=new_token)
            db.session.add(login_token)
            db.session.commit()

            login_user(user)
            return redirect(url_for('user_dashboard'))

        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route("/admin/update_login_price", methods=["POST"])
@login_required
def update_login_price():
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    new_price = request.form["extra_login_price"]
    try:
        set_extra_login_price(float(new_price))
        flash("Extra login price updated successfully!", "success")
    except ValueError:
        flash("Invalid price entered.", "error")

    return redirect(url_for("admin_dashboard"))

@app.route("/purchase_extra_login", methods=["POST"])
@login_required
def purchase_extra_login():
    extra_price = get_extra_login_price()

    try:
        charge = stripe.Charge.create(
            amount=int(extra_price * 100),
            currency="usd",
            description=f"Extra login for {current_user.username}",
            source=request.form["stripeToken"],
        )
        current_user.max_logins += 1  # Increase allowed logins
        db.session.commit()
        flash("Extra login purchased successfully!", "success")
    except stripe.error.StripeError as e:
        flash(f"Payment failed: {e.user_message}", "error")

    return redirect(url_for("user_dashboard"))

@app.route('/logout')
@login_required
def logout():
    if current_user.role != "admin":
        token = session.get('login_token')
        if token:
            db.LoginToken.query.filter_by(token=token).delete()
            db.session.commit()
            session.pop('login_token', None)
        session.clear()
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
    return render_template('admin_dashboard.html', users=users,now=now,monthly_fee=get_monthly_fee())

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('login'))
    if not current_user.is_paid:
        flash('Access restricted. Please contact the admin to make a payment.', 'error')
        return redirect(url_for('login'))
    now = datetime.utcnow().date()
    return render_template('user_dashboard.html',now=now)

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
    if current_user.role != "admin":
        flash("Unauthorized access!", "error")
        return redirect(url_for("admin_dashboard"))

    user = User.query.get_or_404(user_id)
    amount = float(request.form["amount"]) * 100  # Convert dollars to cents

    try:
        charge = stripe.Charge.create(
            amount=int(amount),
            currency="usd",
            description=f"Payment for {user.username}",
            source=request.form["stripeToken"],
        )
        user.is_paid = True
        user.payment_due_date = datetime.utcnow().date() + timedelta(days=30)
        db.session.commit()
        flash("Payment processed successfully!", "success")
    except stripe.error.StripeError as e:
        flash(f"Payment failed: {e.user_message}", "error")

    return redirect(url_for("admin_dashboard"))

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

    flash(f"Stripe payments {'enabled' if user.stripe_enabled else 'disabled'} for {user.username}.", "success")
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
        prorated_fee = round((days_remaining / days_in_month) * 10, 2) if days_remaining > 0 else 10.00
        user.sms_fee_due = prorated_fee
        user.sms_opt_in = True
        flash(f"SMS alerts enabled. Prorated fee: ${prorated_fee}. Please proceed to payment.", "success")
    else:
        user.sms_opt_in = False
        user.sms_fee_due = 0.0
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
        set_monthly_fee(float(new_fee))
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
        flash('Amazon Relay credentials updated successfully.', 'success')
    else:
        flash('Both fields are required.', 'error')
    
    return redirect(url_for('user_dashboard'))


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