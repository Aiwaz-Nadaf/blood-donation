from pymongo import MongoClient

# MongoDB Atlas connection
MONGODB_URI = "mongodb+srv://donate-blood:blooddonate@cluster0.evglf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGODB_URI)

# Connect to the database and collection
db = client.blood_donation
users = db.users

# Get all users
print("\n=== All Users in Database ===")
all_users = users.find()
for user in all_users:
    print("\nUser Details:")
    print(f"Name: {user.get('name')}")
    print(f"Email: {user.get('email')}")
    print(f"Phone: {user.get('phone')}")
    print(f"Blood Group: {user.get('blood_group')}")
    print(f"Location: {user.get('location')}")
    print("-" * 50)

# Get total count of users
total_users = users.count_documents({})
print(f"\nTotal number of users: {total_users}")

# Close the connection
client.close() 