from app import *

def setup_db():
    db.drop_all()
    db.create_all()
    hashed_password = generate_password_hash('password123', method='sha256')

    new_user1 = User(public_id=str(uuid.uuid4()), 
                    name='vaughn', 
                    email='vaughnvilliers@gmail.com',
                    password=hashed_password, 
                    admin=True)

    db.session.add(new_user1)
    db.session.commit()

    new_user2 = User(public_id=str(uuid.uuid4()), 
                    name='allen', 
                    email='s972024@gmail.com',
                    password=hashed_password, 
                    admin=True)

    db.session.add(new_user2)
    db.session.commit()


if __name__ == '__main__':
	setup_db()
