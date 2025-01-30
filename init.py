from app import app, db, User

with app.app_context():
    # Check if admin already exists
    if not User.query.filter_by(username='admin').first():
        admin_user = User(
            username='admin',
            email='admin@example.com',
            phone_number='+11234567890',
            role='admin',
            amazon_relay_email='admin@example.com',
            amazon_relay_password=''
        )
        admin_user.set_password('adminpassword')  # Change password as needed
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created.")
    else:
        print("Admin user already exists.")
