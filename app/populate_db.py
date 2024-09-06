from app import app, db, User

with app.app_context():
    # Create test users with hashed passwords
    user1 = User(username='2203A51579')
    user1.set_password('Umesh@821')
    
    user2 = User(username='BNReddy')
    user2.set_password('BNR@')
    
    # Add to the database
    db.session.add(user1)
    db.session.add(user2)
    db.session.commit()
    
    print("Test users added to the database.")
