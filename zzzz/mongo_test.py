from pymongo import MongoClient

# MongoDB Atlas connection string
uri = "mongodb+srv://main-donate:gpkpjspm@cluster0.togme.mongodb.net/blood_donation?retryWrites=true&w=majority"

try:
    # Create a new client and connect to the server
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    
    # Send a ping to confirm a successful connection
    client.admin.command('ping')
    print("Successfully connected to MongoDB!")
    
    # List all databases
    print("\nAvailable databases:")
    for db_name in client.list_database_names():
        print(f"- {db_name}")
        
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
finally:
    if 'client' in locals():
        client.close()
        print("\nMongoDB connection closed") 