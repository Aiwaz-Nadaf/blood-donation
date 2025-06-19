from pymongo import MongoClient
from dotenv import load_dotenv
import os
from datetime import datetime, UTC

load_dotenv()

def connect_to_mongodb():
    try:
        client = MongoClient(os.getenv('MONGODB_URI'))
        # Test the connection
        client.server_info()
        db = client.blood_donation
        print("Successfully connected to MongoDB")
        return db
    except Exception as e:
        print(f"Error connecting to MongoDB: {str(e)}")
        return None

def check_admin_data():
    db = connect_to_mongodb()
    if db is None:
        return
    
    try:
        admins = list(db.admins.find())
        print("\n=== Admin Users ===")
        if not admins:
            print("No admin users found in the database.")
            return
            
        for admin in admins:
            print(f"\nEmail: {admin.get('email')}")
            print(f"Hospital Name: {admin.get('hospital_name')}")
            print(f"Hospital ID: {admin.get('hospital_id')}")
            print(f"Status: {admin.get('status')}")
            print(f"Created At: {admin.get('created_at')}")
            print("-" * 50)
    except Exception as e:
        print(f"Error checking admin data: {str(e)}")

def check_user_data():
    db = connect_to_mongodb()
    if db is None:
        return
    
    try:
        users = list(db.users.find())
        print("\n=== Blood Donors ===")
        if not users:
            print("No blood donors found in the database.")
            return
            
        for user in users:
            print(f"\nName: {user.get('name')}")
            print(f"Email: {user.get('email')}")
            print(f"Blood Group: {user.get('blood_group')}")
            print(f"Phone: {user.get('phone')}")
            print(f"Address: {user.get('location', {}).get('address')}")
            print(f"Created At: {user.get('created_at')}")
            print("-" * 50)
    except Exception as e:
        print(f"Error checking user data: {str(e)}")

def create_test_admin():
    db = connect_to_mongodb()
    if db is None:
        return
    
    test_admin = {
        'email': 'test@hospital.com',
        'password': 'test123',
        'name': 'Test Hospital',
        'hospital_name': 'Test Hospital',
        'hospital_id': 'TEST001',
        'address': 'Test Location',
        'location': {
            'type': 'Point',
            'coordinates': [0, 0],
            'address': 'Test Location'
        },
        'verification_doc': 'default.pdf',
        'status': 'active',
        'created_at': datetime.now(UTC)
    }
    
    try:
        # Check if admin already exists
        existing_admin = db.admins.find_one({'email': test_admin['email']})
        if existing_admin:
            print(f"\nAdmin with email {test_admin['email']} already exists.")
            return
            
        result = db.admins.insert_one(test_admin)
        print(f"\nCreated test admin with ID: {result.inserted_id}")
        print("You can now login with:")
        print(f"Email: {test_admin['email']}")
        print(f"Password: {test_admin['password']}")
    except Exception as e:
        print(f"Error creating test admin: {str(e)}")

def create_test_user():
    db = connect_to_mongodb()
    if db is None:
        return
    
    test_user = {
        'name': 'Test Donor',
        'email': 'donor@test.com',
        'phone': '+1234567890',
        'blood_group': 'O+',
        'password': 'test123',
        'location': {
            'type': 'Point',
            'coordinates': [0, 0],
            'address': 'Test Location'
        },
        'created_at': datetime.now(UTC)
    }
    
    try:
        # Check if user already exists
        existing_user = db.users.find_one({'email': test_user['email']})
        if existing_user:
            print(f"\nUser with email {test_user['email']} already exists.")
            return
            
        result = db.users.insert_one(test_user)
        print(f"\nCreated test user with ID: {result.inserted_id}")
        print("You can now login with:")
        print(f"Email: {test_user['email']}")
        print(f"Password: {test_user['password']}")
    except Exception as e:
        print(f"Error creating test user: {str(e)}")

if __name__ == "__main__":
    print("\n=== Blood Donation System Database Manager ===")
    
    while True:
        print("\nOptions:")
        print("1. Check Admin Data")
        print("2. Check User Data")
        print("3. Create Test Admin")
        print("4. Create Test User")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == '1':
            check_admin_data()
        elif choice == '2':
            check_user_data()
        elif choice == '3':
            create_test_admin()
        elif choice == '4':
            create_test_user()
        elif choice == '5':
            print("\nExiting...")
            break
        else:
            print("\nInvalid choice. Please try again.") 