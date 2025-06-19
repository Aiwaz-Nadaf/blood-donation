from pymongo import MongoClient

# MongoDB Atlas connection
MONGODB_URI = "mongodb+srv://donate-blood:blooddonate@cluster0.evglf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGODB_URI)
db = client.blood_donation
users = db.users

def print_user_data():
    print("\n=== User Data in Database ===")
    print("-" * 50)
    
    # Get all users
    all_users = list(users.find())
    
    if not all_users:
        print("No user data found in the database.")
        return
    
    for user in all_users:
        print("\nUser Details:")
        print(f"Name: {user.get('name', 'N/A')}")
        print(f"Email: {user.get('email', 'N/A')}")
        print(f"Phone: {user.get('phone', 'N/A')}")
        print(f"Blood Group: {user.get('blood_group', 'N/A')}")
        
        if 'location' in user:
            print("\nLocation Details:")
            print(f"Latitude: {user['location'].get('coordinates', [0, 0])[1]}")
            print(f"Longitude: {user['location'].get('coordinates', [0, 0])[0]}")
            print(f"Address: {user['location'].get('address', 'N/A')}")
        
        print("-" * 50)

if __name__ == "__main__":
    print_user_data() 