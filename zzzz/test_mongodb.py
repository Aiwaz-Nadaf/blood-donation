from pymongo import MongoClient
import os
from dotenv import load_dotenv
import sys
from pathlib import Path

# Get the absolute path of the current file
current_dir = Path(__file__).resolve().parent

# Load the .env file from the same directory as this script
load_dotenv(current_dir / '.env')

def test_connection():
    try:
        # Get the connection string from .env
        uri = os.getenv('MONGODB_URI')
        if not uri:
            print("Error: MONGODB_URI not found in .env file")
            sys.exit(1)
            
        print("Connecting to MongoDB...")
        print(f"Connection string: {uri}")
        
        # Create a new client and connect to the server
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        
        # Send a ping to confirm a successful connection
        client.admin.command('ping')
        print("Successfully connected to MongoDB!")
        
        # Create a test document
        db = client.blood_donation
        test_data = {"test": "connection"}
        result = db.test_collection.insert_one(test_data)
        print(f"Inserted test document with id: {result.inserted_id}")
        
        # Clean up
        db.test_collection.delete_one({"test": "connection"})
        print("Test document deleted")
        
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
    finally:
        if 'client' in locals():
            client.close()
            print("MongoDB connection closed")

if __name__ == "__main__":
    test_connection() 