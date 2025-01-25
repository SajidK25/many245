from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)
    if not current_user.is_paid:
        flash('Access restricted. Please contact the admin to make a payment.')
        return redirect(url_for('login'))
    return render_template('user_dashboard.html')

@app.route('/admin/mark_paid/<int:user_id>', methods=['POST'])
@login_required
def mark_paid(user_id):
    if current_user.role != 'admin':
        flash('Unauthorized access!')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    user.is_paid = True
    user.payment_due_date = datetime.utcnow() + timedelta(days=30)
    payment = Payment(user_id=user.id, amount=30.0)
    db.session.add(payment)
    db.session.commit()
    flash(f'{user.username} marked as paid until {user.payment_due_date.strftime("%Y-%m-%d")}')
    return redirect(url_for('dashboard'))

@app.route('/admin/view_payments')
@login_required
def view_payments():
    if current_user.role != 'admin':
        flash('Unauthorized access!')
        return redirect(url_for('dashboard'))

    payments = Payment.query.order_by(Payment.date.desc()).all()
    return render_template('payments.html', payments=payments)

# Database Initialization Command
@app.cli.command('initdb')
def initdb():
    db.create_all()
    print('Database initialized.')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
