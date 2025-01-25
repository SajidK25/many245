from app import db, User

# Create a new admin user
admin_user = User(username='admin', role='admin')
admin_user.set_password('adminpassword')  # Replace 'adminpassword' with your desired password

# Add the admin user to the database
db.session.add(admin_user)
db.session.commit()

print("Admin user created with username 'admin' and the password you set.")
