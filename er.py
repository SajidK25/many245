from app import db
db.create_all()  # Attempt to create tables
print("Tables created:", db.metadata.tables.keys())
