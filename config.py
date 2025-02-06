import os

class Config:
    SECRET_KEY = os.urandom(24)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///instance/site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = "your_secret_key"
    # SMTP Configuration
    MAIL_SERVER = "your_smtp_server"
    MAIL_PORT = 587  # Use 465 for SSL
    MAIL_USE_TLS = True
    MAIL_USERNAME = "your_email@example.com"
    MAIL_PASSWORD = "your_email_password"
    MAIL_DEFAULT_SENDER = "your_email@example.com"
