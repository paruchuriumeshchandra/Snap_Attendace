from app import app, db, User

with app.app_context():
    # Query all users in the database
    users = User.query.all()
    
    # Print each user
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}, Password: {user.password}")

    if not users:
        print("No users found in the database.")
