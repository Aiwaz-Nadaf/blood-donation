from pymongo import MongoClient

# MongoDB Atlas connection
MONGODB_URI = "mongodb+srv://donate-blood:blooddonate@cluster0.evglf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGODB_URI)

# List all databases
print("\n=== Available Databases ===")
for db_name in client.list_database_names():
    print(f"\nDatabase: {db_name}")
    # Get the database object
    db = client[db_name]
    # List all collections in the database
    collections = db.list_collection_names()
    print("Collections:")
    for collection in collections:
        print(f"  - {collection}")
        # Get count of documents in each collection
        count = db[collection].count_documents({})
        print(f"    Documents: {count}")

# Close the connection
client.close() 