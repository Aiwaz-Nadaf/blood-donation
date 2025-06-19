from pymongo import MongoClient

# MongoDB Atlas connection
MONGODB_URI = "mongodb+srv://donate-blood:blooddonate@cluster0.evglf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGODB_URI)
db = client.blood_donation
admins = db.admins

def print_admin_data():
    print("\n=== Admin Data in Database ===")
    print("-" * 50)
    
    # Get all admins
    all_admins = list(admins.find())
    
    if not all_admins:
        print("No admin data found in the database.")
        return
    
    for admin in all_admins:
        print("\nHospital Details:")
        print(f"Hospital Name: {admin.get('hospital_name', 'N/A')}")
        print(f"Hospital ID: {admin.get('hospital_id', 'N/A')}")
        print(f"Email: {admin.get('email', 'N/A')}")
        print(f"Address: {admin.get('address', 'N/A')}")
        print(f"Status: {admin.get('status', 'N/A')}")
        print(f"Verification Document: {admin.get('verification_doc', 'N/A')}")
        
        if 'location' in admin:
            print("\nLocation Details:")
            print(f"Latitude: {admin['location'].get('coordinates', [0, 0])[1]}")
            print(f"Longitude: {admin['location'].get('coordinates', [0, 0])[0]}")
            print(f"Address: {admin['location'].get('address', 'N/A')}")
        
        print("-" * 50)

if __name__ == "__main__":
    print_admin_data() 