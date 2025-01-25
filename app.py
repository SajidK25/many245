from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sample_secret_key_123456'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # 'admin' or 'user'
    is_paid = db.Column(db.Boolean, default=False)
    payment_due_date = db.Column(db.Date, nullable=True)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=30.0)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_method = db.Column(db.String(20), nullable=False)  # 'cash', 'check', 'credit_card'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check for duplicate username
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        try:
            user = User(username=username)
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')

            # Redirect based on user role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
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
    return render_template('admin_dashboard.html', users=users)

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('login'))
    if not current_user.is_paid:
        flash('Access restricted. Please contact the admin to make a payment.', 'error')
        return redirect(url_for('login'))
    return render_template('user_dashboard.html')

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        flash('Unauthorized access!', 'error')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        user.username = username
        user.role = role
        if password:
            user.set_password(password)
        
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
