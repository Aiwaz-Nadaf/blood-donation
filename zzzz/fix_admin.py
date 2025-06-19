from pymongo import MongoClient
from dotenv import load_dotenv
import os
from datetime import datetime, UTC

load_dotenv()

def connect_to_mongodb():
    try:
        client = MongoClient(os.getenv('MONGODB_URI'))
        db = client.blood_donation
        admins = db.admins
        print("Successfully connected to MongoDB")
        return admins
    except Exception as e:
        print(f"MongoDB connection error: {str(e)}")
        return None

def fix_admin_status():
    admins = connect_to_mongodb()
    if admins is None:
        return
    
    # Create default admin if not exists
    default_admin = {
        'email': 'admin@blooddonation.com',
        'password': 'admin123',
        'name': 'Admin',
        'hospital_name': 'System Admin',
        'hospital_id': 'ADMIN001',
        'address': 'System',
        'location': {
            'type': 'Point',
            'coordinates': [0, 0],
            'address': 'System'
        },
        'verification_doc': 'default.pdf',
        'status': 'active',
        'created_at': datetime.now(UTC)
    }
    
    # Check if default admin exists
    existing_admin = admins.find_one({'email': default_admin['email']})
    if not existing_admin:
        admins.insert_one(default_admin)
        print("Created default admin account")
    
    # Update all admin accounts to active status
    result = admins.update_many(
        {},
        {'$set': {'status': 'active'}}
    )
    
    print(f"Updated {result.modified_count} admin accounts to active status")
    
    # Display all admin accounts
    print("\nCurrent admin accounts:")
    for admin in admins.find():
        print(f"Email: {admin.get('email', 'No email')}")
        print(f"Hospital: {admin.get('hospital_name', 'No hospital name')}")
        print(f"Status: {admin.get('status', 'No status')}")
        print("---")

if __name__ == "__main__":
    print("=== Fixing Admin Account Status ===")
    fix_admin_status() 