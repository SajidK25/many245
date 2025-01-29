from app2 import app,db, User

with app.app_context():
    # Create a new admin user
    admin_user = User(username='admin',email='admin@example.com',phone_number='+11234567890', role='admin',amazon_relay_email='admin@example.com', amazon_relay_password='')
    admin_user.set_password('adminpassword')  # Replace 'adminpassword' with your desired password

    # Add the admin user to the database
    db.session.add(admin_user)
    db.session.commit()

    print("Admin user created with username 'admin' and the password you set.")
