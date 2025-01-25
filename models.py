from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, name="uq_user_username")  # Named unique constraint
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    amazon_relay_email = db.Column(db.String(120), unique=True, nullable=True, name="uq_user_amazon_relay_email")
    amazon_relay_password = db.Column(db.String(60), nullable=True)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def set_amazon_relay_password(self, password):
        self.amazon_relay_password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_amazon_relay_password(self, password):
        return bcrypt.check_password_hash(self.amazon_relay_password, password)
