from pymongo import MongoClient
from geopy.distance import geodesic
import math

# MongoDB Atlas connection
MONGODB_URI = "mongodb+srv://donate-blood:blooddonate@cluster0.evglf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGODB_URI)
db = client.blood_donation
users = db.users

def find_nearby_donors(latitude, longitude, blood_group, max_distance_km=10):
    """
    Find donors within specified distance and matching blood group
    """
    print(f"\nSearching for {blood_group} donors within {max_distance_km}km...")
    
    # Get all donors with matching blood group
    donors = users.find({"blood_group": blood_group})
    
    # Reference point (searcher's location)
    ref_point = (latitude, longitude)
    
    found_donors = []
    for donor in donors:
        # Get donor's coordinates
        donor_coords = donor['location']['coordinates']
        donor_point = (donor_coords[1], donor_coords[0])  # Convert to (lat, lon)
        
        # Calculate distance
        distance = geodesic(ref_point, donor_point).kilometers
        
        if distance <= max_distance_km:
            found_donors.append({
                'name': donor['name'],
                'phone': donor['phone'],
                'address': donor['location']['address'],
                'distance': round(distance, 2)
            })
    
    return found_donors

def main():
    # Example search (using Pune coordinates)
    search_lat = 18.476856192525837
    search_lon = 73.93186471299222
    blood_group = "AB+"
    
    print("\n=== Blood Donor Search ===")
    print(f"Search Location: {search_lat}, {search_lon}")
    print(f"Blood Group: {blood_group}")
    
    # Find donors within 10km
    donors = find_nearby_donors(search_lat, search_lon, blood_group, 10)
    
    if donors:
        print(f"\nFound {len(donors)} donors:")
        for donor in donors:
            print("\nDonor Details:")
            print(f"Name: {donor['name']}")
            print(f"Phone: {donor['phone']}")
            print(f"Address: {donor['address']}")
            print(f"Distance: {donor['distance']}km")
            print("-" * 50)
    else:
        print("\nNo donors found within the specified distance.")

if __name__ == "__main__":
    main() 