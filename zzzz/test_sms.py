import os
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

# Get API key
FAST2SMS_API_KEY = os.getenv('FAST2SMS_API_KEY')
FAST2SMS_API_URL = "https://www.fast2sms.com/dev/bulkV2"

def test_sms():
    try:
        # Test phone number (replace with your number)
        phone_number = "7745863295"  # Replace with your actual phone number
        
        # Test message
        message = "This is a test message from Blood Donation System"
        
        # Prepare payload
        payload = {
            "route": "q",  # Using quick route
            "numbers": phone_number,
            "message": message,
            "language": "english"
        }
        
        # Set up headers with API key
        headers = {
            "authorization": FAST2SMS_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # Send SMS
        response = requests.post(FAST2SMS_API_URL, data=payload, headers=headers)
        
        # Check response
        if response.status_code == 200:
            result = response.json()
            if result.get('return'):
                print("✅ SMS sent successfully!")
                print(f"Request ID: {result.get('request_id')}")
                return True
            else:
                print("❌ Failed to send SMS")
                print(f"Error: {result.get('message', 'Unknown error')}")
                return False
        else:
            print("❌ Failed to send SMS")
            print(f"Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

if __name__ == "__main__":
    print("Testing Fast2SMS Integration...")
    test_sms() 