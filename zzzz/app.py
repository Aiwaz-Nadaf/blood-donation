from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, g
from pymongo import MongoClient
from geopy.geocoders import Nominatim
from geopy.exc import GeocoderTimedOut
import os
from dotenv import load_dotenv
from bson import ObjectId
from werkzeug.utils import secure_filename
from math import radians, sin, cos, sqrt, atan2, asin
from datetime import datetime, timedelta
import pytz
from functools import wraps
import json
from config import Config
import requests
from utils import (
    hash_password, verify_password, validate_email, validate_phone,
    validate_coordinates, admin_required, user_required, log_error,
    format_datetime, sanitize_filename, logger
)
import time
import pywhatkit
from translate import Translator
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from mobile_auth import mobile_auth_required, generate_token
import jwt

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# App configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')  # Use environment variable
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# MongoDB configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://donate-blood:jspmdonate@cluster0.evglf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
DB_NAME = os.getenv('DB_NAME', 'blood_donation')

try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    # Test the connection
    client.server_info()
    logger.info("Successfully connected to MongoDB")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {str(e)}")
    raise

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure CORS to allow requests from the Flutter web app
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000", "http://localhost:5000", "http://127.0.0.1:5000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Fast2SMS Configuration
FAST2SMS_API_KEY = os.getenv('FAST2SMS_API_KEY')
FAST2SMS_API_URL = "https://www.fast2sms.com/dev/bulkV2"

# Add translation cache
translation_cache = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Add this function after the MongoDB connection setup
def ensure_default_admin():
    try:
        # Check if default admin exists
        default_admin = admins.find_one({'email': 'admin@blooddonation.com'})
        if not default_admin:
            print("Default admin not found. Creating...")
            default_admin_data = {
                'email': 'admin@blooddonation.com',
                'password': 'admin123',  # Store plain password as per requirements
                'name': 'Admin',
                'hospital_name': 'System Admin',
                'hospital_id': 'ADMIN001',
                'phone': '1234567890',
                'address': 'System',
                'location': {
                    'type': 'Point',
                    'coordinates': [0, 0],
                    'address': 'System'
                },
                'verification_doc': 'default.pdf',
                'status': 'active',  # Set status to active
                'created_at': datetime.now(pytz.UTC)
            }
            result = admins.insert_one(default_admin_data)
            print(f"Created default admin account with ID: {result.inserted_id}")
        else:
            print("Default admin account exists")
            # Ensure the default admin is active
            admins.update_one(
                {'email': 'admin@blooddonation.com'},
                {'$set': {'status': 'active'}}
            )
        
    except Exception as e:
        print(f"Error ensuring default admin: {str(e)}")
        raise

# Call the function after MongoDB connection
try:
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    users = db['users']
    admins = db['admins']
    notifications = db['notifications']
    donation_history = db['donation_history']  # Collection for donation history
    notice_cards = db['notice_cards']  # Collection for notice cards
    
    # Test the connection
    client.server_info()
    logger.info("Successfully connected to MongoDB Atlas")
    
    # Ensure default admin exists
    ensure_default_admin()
    
    # Create indexes for better query performance
    users.create_index([("email", 1)], unique=True)
    users.create_index([("location", "2dsphere")])
    users.create_index([("blood_group", 1)])
    users.create_index([("age", 1)])
    users.create_index([("gender", 1)])
    users.create_index([("last_donation_date", 1)])
    users.create_index([("weight", 1)])
    users.create_index([("height", 1)])
    admins.create_index([("email", 1)], unique=True)
    admins.create_index([("hospital_id", 1)], unique=True)
    donation_history.create_index([("user_id", 1)])
    donation_history.create_index([("donation_date", 1)])
    notice_cards.create_index([("created_at", -1)])
    logger.info("Database indexes created successfully")
    
except Exception as e:
    logger.error(f"MongoDB connection error: {str(e)}")
    raise Exception("Failed to connect to MongoDB Atlas. Please check your connection string and network.")

def translate_text(text, target_language):
    """
    Translate text to the target language using translate package with caching
    """
    try:
        # Return original text if target language is English
        if target_language == 'en':
            return text
            
        # Check cache first
        cache_key = f"{text}_{target_language}"
        if cache_key in translation_cache:
            return translation_cache[cache_key]
            
        # Add delay to avoid rate limiting
        time.sleep(0.5)
        
        # Create a translator instance for the target language
        translator = Translator(to_lang=target_language)
        
        # Attempt translation
        result = translator.translate(text)
        
        # Cache the result
        translation_cache[cache_key] = result
        return result
        
    except Exception as e:
        print(f"Translation error for '{text}': {str(e)}")
        # Return original text on error
        return text

def get_translations(language):
    """Get translations for the specified language"""
    # Default English translations
    translations = {
        'en': {
            'login': 'Login',
            'signup': 'Sign Up',
            'email': 'Email',
            'password': 'Password',
            'name': 'Name',
            'blood_group': 'Blood Group',
            'phone': 'Phone',
            'location': 'Location',
            'age': 'Age',
            'height': 'Height (cm)',
            'weight': 'Weight (kg)',
            'gender': 'Gender',
            'last_donation': 'Last Donation Date',
            'submit': 'Submit',
            'cancel': 'Cancel',
            'logout': 'Logout',
            'dashboard': 'Dashboard',
            'profile': 'Profile',
            'donation_history': 'Donation History',
            'upcoming_camps': 'Upcoming Camps',
            'notifications': 'Notifications',
            'settings': 'Settings',
            'language': 'Language',
            'theme': 'Theme',
            'dark_mode': 'Dark Mode',
            'light_mode': 'Light Mode',
            'system': 'System',
            'about': 'About',
            'contact': 'Contact',
            'help': 'Help',
            'privacy_policy': 'Privacy Policy',
            'terms_of_service': 'Terms of Service',
            'email_exists': 'Email already registered',
            'registration_success': 'Registration successful! Please login.',
            'registration_error': 'Registration failed. Please try again.',
            'missing_field': 'Missing required field: {}',
            'invalid_credentials': 'Invalid email or password',
            'login_success': 'Login successful!',
            'logout_success': 'Logout successful!',
            'profile_updated': 'Profile updated successfully!',
            'error': 'Error',
            'success': 'Success',
            'warning': 'Warning',
            'info': 'Info',
            'confirm': 'Confirm',
            'delete': 'Delete',
            'edit': 'Edit',
            'save': 'Save',
            'search': 'Search',
            'filter': 'Filter',
            'sort': 'Sort',
            'clear': 'Clear',
            'apply': 'Apply',
            'reset': 'Reset',
            'back': 'Back',
            'next': 'Next',
            'previous': 'Previous',
            'first': 'First',
            'last': 'Last',
            'loading': 'Loading...',
            'no_data': 'No data available',
            'no_results': 'No results found',
            'error_occurred': 'An error occurred',
            'try_again': 'Please try again',
            'connection_error': 'Connection error',
            'server_error': 'Server error',
            'unauthorized': 'Unauthorized',
            'forbidden': 'Forbidden',
            'not_found': 'Not found',
            'bad_request': 'Bad request',
            'internal_error': 'Internal server error',
            'service_unavailable': 'Service unavailable',
            'gateway_timeout': 'Gateway timeout',
            'too_many_requests': 'Too many requests',
            'request_timeout': 'Request timeout',
            'conflict': 'Conflict',
            'gone': 'Gone',
            'precondition_failed': 'Precondition failed',
            'unprocessable_entity': 'Unprocessable entity',
            'locked': 'Locked',
            'failed_dependency': 'Failed dependency',
            'upgrade_required': 'Upgrade required',
            'precondition_required': 'Precondition required',
            'too_many_connections': 'Too many connections',
            'retry_with': 'Retry with',
            'unavailable_for_legal_reasons': 'Unavailable for legal reasons',
            'internal_server_error': 'Internal server error',
            'not_implemented': 'Not implemented',
            'bad_gateway': 'Bad gateway',
            'service_unavailable': 'Service unavailable',
            'gateway_timeout': 'Gateway timeout',
            'http_version_not_supported': 'HTTP version not supported',
            'variant_also_negotiates': 'Variant also negotiates',
            'insufficient_storage': 'Insufficient storage',
            'loop_detected': 'Loop detected',
            'not_extended': 'Not extended',
            'network_authentication_required': 'Network authentication required',
        },
        'hi': {
            # Hindi translations (add as needed)
            'login': 'लॉग इन',
            'signup': 'साइन अप',
            'email': 'ईमेल',
            'password': 'पासवर्ड',
            'name': 'नाम',
            'blood_group': 'रक्त समूह',
            'phone': 'फोन',
            'location': 'स्थान',
            'age': 'आयु',
            'height': 'ऊंचाई (सेमी)',
            'weight': 'वजन (किलो)',
            'gender': 'लिंग',
            'last_donation': 'अंतिम दान तिथि',
            'submit': 'जमा करें',
            'cancel': 'रद्द करें',
            'logout': 'लॉग आउट',
            'dashboard': 'डैशबोर्ड',
            'profile': 'प्रोफ़ाइल',
            'donation_history': 'दान इतिहास',
            'upcoming_camps': 'आगामी शिविर',
            'notifications': 'सूचनाएं',
            'settings': 'सेटिंग्स',
            'language': 'भाषा',
            'theme': 'थीम',
            'dark_mode': 'डार्क मोड',
            'light_mode': 'लाइट मोड',
            'system': 'सिस्टम',
            'about': 'के बारे में',
            'contact': 'संपर्क',
            'help': 'मदद',
            'privacy_policy': 'गोपनीयता नीति',
            'terms_of_service': 'सेवा की शर्तें',
            'email_exists': 'ईमेल पहले से पंजीकृत है',
            'registration_success': 'पंजीकरण सफल! कृपया लॉगिन करें।',
            'registration_error': 'पंजीकरण विफल। कृपया पुनः प्रयास करें।',
            'missing_field': 'अनिवार्य फ़ील्ड गायब है: {}',
            'invalid_credentials': 'अमान्य ईमेल या पासवर्ड',
            'login_success': 'लॉगिन सफल!',
            'logout_success': 'लॉगआउट सफल!',
            'profile_updated': 'प्रोफ़ाइल सफलतापूर्वक अपडेट किया गया!',
        }
    }
    
    # Error page translations
    translations['404_title'] = 'Page Not Found'
    translations['404_message'] = 'The page you are looking for does not exist.'
    translations['500_title'] = 'Server Error'
    translations['500_message'] = 'An internal server error occurred. Please try again later.'
    translations['403_title'] = 'Access Denied'
    translations['403_message'] = 'You do not have permission to access this page.'
    
    # Home page translations
    translations['home'] = 'Home'
    
    return translations.get(language, translations['en'])

def send_sms(phone_number, message):
    """Send SMS using Fast2SMS API"""
    try:
        # Format phone number (remove any non-digit characters)
        phone_number = ''.join(filter(str.isdigit, phone_number))
        
        # Prepare the payload
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
        
        # Send the SMS
        response = requests.post(FAST2SMS_API_URL, data=payload, headers=headers)
        
        # Check response
        if response.status_code == 200:
            result = response.json()
            if result.get('return'):
                message_id = result.get('request_id')
                print(f"SMS sent successfully. Request ID: {message_id}")
                return message_id
            else:
                error_msg = f"Failed to send SMS: {result.get('message', 'Unknown error')}"
                print(error_msg)
                raise Exception(error_msg)
        else:
            error_msg = f"Failed to send SMS: {response.text}"
            print(error_msg)
            raise Exception(error_msg)
            
    except Exception as e:
        print(f"Error sending SMS: {str(e)}")
        raise e

def send_whatsapp_message(phone_number, message):
    """Send WhatsApp message using pywhatkit"""
    try:
        # Format phone number (remove any non-digit characters)
        phone_number = ''.join(filter(str.isdigit, phone_number))
        
        # Add country code if not present
        if not phone_number.startswith('91'):  # Assuming Indian numbers
            phone_number = '91' + phone_number
            
        # Get current time and add 1 minute for scheduling
        now = datetime.now()
        schedule_time = now + timedelta(minutes=1)
        
        # Send WhatsApp message
        pywhatkit.sendwhatmsg(
            phone_no=f"+{phone_number}",
            message=message,
            time_hour=schedule_time.hour,
            time_min=schedule_time.minute,
            wait_time=20,  # Wait for 20 seconds to load WhatsApp Web
            tab_close=True,  # Close the tab after sending
            close_time=3  # Wait 3 seconds before closing
        )
        
        print(f"WhatsApp message sent successfully to {phone_number}")
        return True
        
    except Exception as e:
        print(f"Error sending WhatsApp message: {str(e)}")
        raise e

def send_message_with_retry(phone_number, message, max_retries=3, use_whatsapp=False):
    """Send message with retry logic"""
    for attempt in range(max_retries):
        try:
            if use_whatsapp:
                success = send_whatsapp_message(phone_number, message)
            else:
                message_id = send_sms(phone_number, message)
                success = True
            return success
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"Failed to send message after {max_retries} attempts: {str(e)}")
                raise e
            print(f"Attempt {attempt + 1} failed, retrying... Error: {str(e)}")
            time.sleep(1)

@app.route('/api/set_language', methods=['POST'])
def set_language():
    """
    Set the user's preferred language
    """
    language = request.form.get('language', 'en')
    session['language'] = language
    return jsonify({'status': 'success'})

# Update the main route to include translations
@app.route('/')
def landing():
    language = session.get('language', 'en')
    translations = get_translations(language)
    return render_template('landing.html', translations=translations)

@app.route('/admin')
def admin_landing():
    language = session.get('language', 'en')
    translations = get_translations(language)
    return render_template('admin_landing.html', translations=translations)

# Update the login route to include translations
@app.route('/login', methods=['GET', 'POST'])
def login():
    language = session.get('language', 'en')
    translations = get_translations(language)
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            # Find user by email
            user = users.find_one({'email': email})
            
            if user and check_password_hash(user['password'], password):
                # Set user session
                session['user'] = str(user['_id'])
                session['user_name'] = user['name']
                session['user_email'] = user['email']
                
                # Log successful login
                print(f"User {user['email']} logged in successfully")
                
                # Flash success message
                flash(translations['login_success'])
                
                # Redirect to dashboard
                return redirect(url_for('dashboard'))
            else:
                # Log failed login attempt
                print(f"Failed login attempt for email: {email}")
                flash(translations['invalid_credentials'])
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            flash(translations['error_message'])
    
    return render_template('login.html', translations=translations)

# Update the signup route to include translations
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    language = session.get('language', 'en')
    translations = get_translations(language)
    
    if request.method == 'POST':
        try:
            # Check if the request is JSON (API) or form data (web)
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form.to_dict()
            
            # Validate required fields
            required_fields = ['name', 'email', 'password', 'blood_group', 'phone', 
                             'location', 'latitude', 'longitude', 'age', 'height', 
                             'weight', 'gender']
            for field in required_fields:
                if field not in data:
                    if request.is_json:
                        return jsonify({'message': f'Missing required field: {field}'}), 400
                    else:
                        flash(translations.get('missing_field', 'Missing required field: {}').format(field=field))
                        return render_template('signup.html', translations=translations)
            
            # Check if user already exists
            if users.find_one({'email': data['email']}):
                if request.is_json:
                    return jsonify({'message': 'Email already registered'}), 400
                else:
                    flash(translations.get('email_exists', 'Email already registered'))
                    return render_template('signup.html', translations=translations)
            
            # Get last donation date if provided
            last_donation = data.get('last_donation')
            
            # Format location for geospatial indexing
            location_data = {
                'type': 'Point',
                'coordinates': [float(data['longitude']), float(data['latitude'])],
                'address': data['location']
            }
            
            # Create new user
            user = {
                'name': data['name'],
                'email': data['email'],
                'password': generate_password_hash(data['password']),
                'blood_group': data['blood_group'],
                'phone': data['phone'],
                'location': location_data,
                'latitude': float(data['latitude']),
                'longitude': float(data['longitude']),
                'age': int(data['age']),
                'height': float(data['height']),
                'weight': float(data['weight']),
                'gender': data['gender'],
                'last_donation': last_donation,
                'created_at': datetime.now(pytz.UTC),
                'role': 'user',
                'is_eligible': True if not last_donation else (
                    datetime.now(pytz.UTC) - 
                    datetime.strptime(last_donation, '%Y-%m-%d').replace(tzinfo=pytz.UTC)
                ).days >= 120
            }
            
            users.insert_one(user)
            
            if request.is_json:
                return jsonify({'message': 'User registered successfully'}), 201
            else:
                flash(translations.get('registration_success', 'Registration successful! Please login.'))
                return redirect(url_for('login'))
                
        except Exception as e:
            if request.is_json:
                return jsonify({'message': str(e)}), 500
            else:
                flash(translations.get('registration_error', 'Registration failed. Please try again.'))
                return render_template('signup.html', translations=translations)
    
    return render_template('signup.html', translations=translations)

# Update the dashboard route to include translations
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash(get_translations(session.get('language', 'en'))['login_required'])
        return redirect(url_for('login'))
        
    language = session.get('language', 'en')
    translations = get_translations(language)
    
    try:
        user_id = session['user']
        user = users.find_one({'_id': ObjectId(user_id)})
        
        if not user:
            session.pop('user', None)
            flash(translations['error_message'])
            return redirect(url_for('login'))
            
        # Get user's donation history
        user_donations = list(donation_history.find({'user_id': str(user_id)}).sort('donation_date', -1))
        
        # Get upcoming blood donation camps
        upcoming_camps = list(admins.find({
            'location': {
                '$near': {
                    '$geometry': {
                        'type': 'Point',
                        'coordinates': user['location']['coordinates']
                    },
                    '$maxDistance': 10000
                }
            }
        }).sort('location.coordinates', 1).limit(5))
        
        # Get pending blood requests
        pending_requests = list(notifications.find({
            'user_id': str(user_id),
            'type': 'blood_request',
            'status': 'pending'
        }).sort('created_at', -1))
        
        return render_template('dashboard.html',
                             user=user,
                             donation_history=user_donations,
                             upcoming_camps=upcoming_camps,
                             pending_requests=pending_requests,
                             translations=translations)
                             
    except Exception as e:
        print(f"Error in dashboard: {str(e)}")
        flash(translations['error_message'])
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    language = session.get('language', 'en')
    translations = get_translations(language)
    
    session.clear()
    flash(translations['logout_success'])
    return redirect(url_for('landing'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    try:
        data = request.json
        user_id = ObjectId(session['user'])
        
        update_data = {
            'name': data.get('name'),
            'phone': data.get('phone'),
            'blood_group': data.get('blood_group')
        }
        
        users.update_one(
            {'_id': user_id},
            {'$set': update_data}
        )
        
        return jsonify({'message': 'Profile updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def haversine_distance(lat1, lon1, lat2, lon2):
    """
    Calculate the great circle distance between two points 
    on the earth (specified in decimal degrees)
    """
    R = 6371  # Earth's radius in kilometers
    
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * atan2(sqrt(a), sqrt(1-a))
    distance = R * c
    
    return distance

@app.route('/admin/user/<user_id>', methods=['GET'])
@admin_required
def get_user_details(user_id):
    try:
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        # Get last notification for this user
        last_notification = notifications.find_one(
            {'user_id': str(user['_id'])},
            sort=[('created_at', -1)]
        )
        
        # Convert ObjectId to string and format dates
        user['_id'] = str(user['_id'])
        if last_notification:
            last_notification['_id'] = str(last_notification['_id'])
            last_notification['created_at'] = last_notification['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify({
            'success': True,
            'user': user,
            'last_notification': last_notification
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def calculate_donor_score(donor, distance, last_notification):
    """
    Calculate a score for a donor based on various factors
    """
    score = 0.0
    
    # Distance factor (closer is better)
    max_distance = 5  # 5km
    distance_factor = 1 - (min(distance, max_distance) / max_distance)
    score += distance_factor * 0.4  # 40% weight
    
    # Last notification factor (longer since last notification is better)
    if last_notification:
        days_since_notification = (datetime.now(pytz.UTC) - last_notification['created_at']).days
        notification_factor = min(days_since_notification / 30, 1)  # Cap at 30 days
        score += notification_factor * 0.3  # 30% weight
    
    # Donation history factor
    if 'last_donation_date' in donor:
        last_donation = donor['last_donation_date']
        if isinstance(last_donation, str):
            last_donation = datetime.fromisoformat(last_donation.replace('Z', '+00:00'))
        days_since_donation = (datetime.now(pytz.UTC) - last_donation).days
        donation_factor = min(days_since_donation / 90, 1)  # Cap at 90 days
        score += donation_factor * 0.3  # 30% weight
    
    return score

@app.route('/admin/search_donors', methods=['POST'])
@admin_required
def search_donors():
    try:
        # Get search criteria from form
        blood_group = request.form.get('blood_group')
        max_distance = float(request.form.get('distance', 5))  # Default to 5km
        
        # Get admin's hospital location
        admin = admins.find_one({'_id': ObjectId(session['admin'])})
        if not admin or 'location' not in admin:
            return jsonify({'error': 'Hospital location not found'}), 400
            
        admin_lat = float(admin['location']['coordinates'][1])
        admin_lon = float(admin['location']['coordinates'][0])
        
        # Build the query
        query = {}
        
        # Add blood group filter if specified
        if blood_group:
            query['blood_group'] = blood_group
            
        # Get all matching donors based on blood group
        matching_donors = []
        donors = list(users.find(query))  # Convert cursor to list
        
        print(f"Found {len(donors)} total donors in database")  # Debug print
        
        for donor in donors:
            # Skip donors who have already responded to requests for this blood group
            existing_response = notifications.find_one({
                'user_id': str(donor['_id']),
                'type': 'blood_request',
                'data.blood_group_needed': blood_group,
                'status': {'$in': ['responded', 'selected']}
            })
            
            if existing_response:
                print(f"Donor {donor.get('name', 'Unknown')} has already responded to a request for blood group {blood_group}")
                continue
                
            # Skip donors in cooldown period
            if 'last_donation_date' in donor:
                last_donation = donor['last_donation_date']
                if isinstance(last_donation, str):
                    last_donation = datetime.fromisoformat(last_donation.replace('Z', '+00:00'))
                cooldown_end = last_donation + timedelta(days=90)
                if datetime.now(pytz.UTC) < cooldown_end:
                    print(f"Donor {donor.get('name', 'Unknown')} is in cooldown period")
                    continue
            
            if 'location' not in donor:
                print(f"Donor {donor.get('name', 'Unknown')} has no location data")
                continue
                
            # Get donor's coordinates
            donor_lat = float(donor['location']['coordinates'][1])
            donor_lon = float(donor['location']['coordinates'][0])
            
            # Calculate distance using Haversine formula
            distance = haversine_distance(
                admin_lat, admin_lon,
                donor_lat, donor_lon
            )
            
            print(f"Donor {donor.get('name', 'Unknown')} is {distance:.2f}km away")
            
            # Only include donors within the specified distance
            if distance <= max_distance:
                # Get last notification for this donor
                last_notification = notifications.find_one(
                    {'user_id': str(donor['_id'])},
                    sort=[('created_at', -1)]
                )
                
                # Calculate donor score using AI algorithm
                donor_score = calculate_donor_score(donor, distance, last_notification)
                
                matching_donors.append({
                    'id': str(donor['_id']),
                    'name': donor['name'],
                    'blood_group': donor['blood_group'],
                    'phone': donor.get('phone', 'N/A'),
                    'distance': round(distance, 2),
                    'email': donor['email'],
                    'last_notified': last_notification['created_at'].strftime('%Y-%m-%d %H:%M:%S') if last_notification else None,
                    'address': donor['location'].get('address', 'Address not available'),
                    'score': round(donor_score * 100, 2)
                })
        
        # Sort by donor score (highest first)
        matching_donors.sort(key=lambda x: x['score'], reverse=True)
        
        print(f"Found {len(matching_donors)} matching donors within {max_distance}km")
        
        return jsonify({
            'success': True,
            'donors': matching_donors,
            'count': len(matching_donors)
        })
        
    except Exception as e:
        print(f"Error in search_donors: {str(e)}")
        return jsonify({'error': str(e)}), 500

def format_phone_number(phone):
    """Convert phone number to E.164 format"""
    # Remove any non-digit characters
    phone = ''.join(filter(str.isdigit, phone))
    
    # Add country code if not present
    if not phone.startswith('91'):  # Assuming Indian numbers
        phone = '91' + phone
        
    # Add plus sign
    return '+' + phone

@app.route('/admin/send_alert', methods=['POST'])
def send_alert():
    if 'admin' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        # Get admin details
        admin = admins.find_one({'_id': ObjectId(session['admin'])})
        if not admin:
            return jsonify({'error': 'Admin not found'}), 404
            
        # Get search criteria from request
        blood_group = request.json.get('blood_group')
        max_distance = float(request.json.get('distance', 5))  # Default to 5km
        use_whatsapp = request.json.get('use_whatsapp', False)  # Get WhatsApp preference
        
        # Validate admin's phone number
        admin_phone = admin.get('phone')
        if not admin_phone:
            return jsonify({'error': 'Please add your hospital phone number in your profile first'}), 400
            
        # Get admin's hospital location
        admin_lat = float(admin['location']['coordinates'][1])
        admin_lon = float(admin['location']['coordinates'][0])
        
        # Build the query for matching donors
        query = {}
        if blood_group:
            query['blood_group'] = blood_group
            
        # Get all matching donors
        matching_donors = []
        donors = list(users.find(query))
        
        print(f"Found {len(donors)} total donors in database")
        
        messages_sent = 0
        notifications_created = 0
        errors = []
        
        for donor in donors:
            if 'location' not in donor:
                continue
                
            # Get donor's coordinates
            donor_lat = float(donor['location']['coordinates'][1])
            donor_lon = float(donor['location']['coordinates'][0])
            
            # Calculate distance using Haversine formula
            distance = haversine_distance(
                admin_lat, admin_lon,
                donor_lat, donor_lon
            )
            
            # Only include donors within the specified distance
            if distance <= max_distance:
                matching_donors.append(donor)
                
                try:
                    # Create notification data
                    notification_data = {
                        'type': 'blood_request',
                        'hospital_name': admin.get('hospital_name', 'Hospital'),
                        'hospital_address': admin.get('address', 'Address not available'),
                        'hospital_phone': admin_phone,
                        'hospital_id': admin.get('hospital_id', 'N/A'),
                        'blood_group_needed': blood_group,
                        'distance': str(round(distance, 2)),
                        'timestamp': str(datetime.now(pytz.UTC)),
                        'request_id': str(ObjectId()),  # Generate unique request ID
                        'status': 'pending',  # Initial status
                        'response': None,  # Will store user's response
                        'response_time': None,  # Will store when user responded
                        'admin_id': str(admin['_id'])  # Store admin ID for reference
                    }
                    
                    # Create notification record in database
                    message_body = f"""🚨 Urgent Blood Request!

Hospital: {admin.get('hospital_name', 'Hospital')}
Blood Group Needed: {blood_group}
Distance: {round(distance, 2)}km
Address: {admin.get('address', 'Address not available')}

Please visit your dashboard to respond to this request:
http://localhost:5001/dashboard

Or call {admin_phone} for details.

Thank you for your support!"""
                    
                    notification_record = {
                        'user_id': str(donor['_id']),
                        'type': 'blood_request',
                        'title': f"🚨 Urgent Blood Request from {admin.get('hospital_name', 'Hospital')}",
                        'body': message_body,
                        'data': notification_data,
                        'created_at': datetime.now(pytz.UTC),
                        'read': False,
                        'message_status': 'pending',
                        'channel': 'whatsapp' if use_whatsapp else 'sms',
                        'request_id': notification_data['request_id'],
                        'status': 'pending',
                        'response': None,
                        'response_time': None,
                        'admin_id': str(admin['_id'])
                    }
                    notifications.insert_one(notification_record)
                    notifications_created += 1
                    
                    # Send message using selected channel
                    try:
                        donor_phone = donor.get('phone')
                        if donor_phone:
                            print(f"Attempting to send {'WhatsApp' if use_whatsapp else 'SMS'} to donor {donor.get('name', 'Unknown')} with phone {donor_phone}")
                            success = send_message_with_retry(
                                donor_phone,
                                message_body,
                                use_whatsapp=use_whatsapp
                            )
                            if success:
                                notifications.update_one(
                                    {'_id': notification_record['_id']},
                                    {'$set': {'message_status': 'sent'}}
                                )
                                messages_sent += 1
                                print(f"Successfully sent {'WhatsApp' if use_whatsapp else 'SMS'} to {donor.get('name', 'Unknown')}")
                        else:
                            error_msg = f"No phone number found for donor {donor.get('name', 'Unknown')}"
                            print(error_msg)
                            errors.append(error_msg)
                    except Exception as e:
                        error_msg = f"Error sending {'WhatsApp' if use_whatsapp else 'SMS'} to {donor.get('name', 'Unknown')}: {str(e)}"
                        print(error_msg)
                        errors.append(error_msg)
                    
                except Exception as e:
                    error_msg = f"Error processing notification for {donor.get('name', 'Unknown')}: {str(e)}"
                    print(error_msg)
                    errors.append(error_msg)
                    continue
        
        return jsonify({
            'success': True,
            'message': f'Notifications created for {notifications_created} donors, {"WhatsApp" if use_whatsapp else "SMS"} sent to {messages_sent} donors',
            'total_matching_donors': len(matching_donors),
            'errors': errors if errors else None
        })
        
    except Exception as e:
        error_msg = f"Error in send_alert: {str(e)}"
        print(error_msg)
        return jsonify({'error': error_msg}), 500

@app.route('/user/notifications', methods=['GET'])
def get_user_notifications():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        # Get all notifications for the user
        user_notifications = list(notifications.find(
            {'user_id': session['user']}
        ).sort('created_at', -1))
        
        # Get unread count
        unread_count = notifications.count_documents({
            'user_id': session['user'],
            'read': False
        })
        
        # Convert ObjectId to string and format dates
        for notif in user_notifications:
            notif['_id'] = str(notif['_id'])
            notif['created_at'] = notif['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            
        return jsonify({
            'success': True,
            'notifications': user_notifications,
            'unread_count': unread_count
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user/mark_notification_read', methods=['POST'])
def mark_notification_read():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        notification_id = request.json.get('notification_id')
        
        # Update notification status
        result = notifications.update_one(
            {
                '_id': ObjectId(notification_id),
                'user_id': session['user']
            },
            {'$set': {'read': True}}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Notification not found'}), 404
            
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/notifications', methods=['GET'])
@admin_required
def get_notifications():
    try:
        # Get all notifications for the admin
        admin_notifications = list(notifications.find({
            'type': 'system'
        }).sort('created_at', -1))
        
        # Convert ObjectId to string for JSON serialization
        for notification in admin_notifications:
            notification['_id'] = str(notification['_id'])
            
        return jsonify({
            'success': True,
            'notifications': admin_notifications
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/users')
def admin_users():
    if 'admin' not in session:
        flash('Please login as admin first')
        return redirect(url_for('admin_login'))
    
    try:
        admin = admins.find_one({'_id': ObjectId(session['admin'])})
        if not admin:
            session.pop('admin', None)
            flash('Admin not found')
            return redirect(url_for('admin_login'))
        
        all_users = list(users.find())
        return render_template('admin_users.html', admin=admin, users=all_users)
    
    except Exception as e:
        session.pop('admin', None)
        flash('Error accessing user list')
        return redirect(url_for('admin_login'))

@app.route('/admin/user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'admin' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    try:
        result = users.delete_one({'_id': ObjectId(user_id)})
        if result.deleted_count:
            return jsonify({'success': True})
        return jsonify({'error': 'User not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user/register_fcm', methods=['POST'])
def register_fcm_token():
    if 'user' not in session:
        print("No user in session for FCM registration")  # Debug log
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        fcm_token = request.json.get('fcm_token')
        if not fcm_token:
            print("No FCM token provided")  # Debug log
            return jsonify({'error': 'FCM token is required'}), 400
            
        user_id = ObjectId(session['user'])
        print(f"Registering FCM token for user ID: {user_id}")  # Debug log
            
        # Update user's FCM token
        result = users.update_one(
            {'_id': user_id},
            {'$set': {'fcm_token': fcm_token}}
        )
        
        if result.modified_count > 0:
            print(f"Successfully registered FCM token for user ID: {user_id}")  # Debug log
            return jsonify({'success': True, 'message': 'FCM token registered successfully'})
        else:
            print(f"User not found for ID: {user_id}")  # Debug log
            return jsonify({'error': 'User not found'}), 404
        
    except Exception as e:
        print(f"Error registering FCM token: {str(e)}")  # Debug log
        return jsonify({'error': str(e)}), 500

@app.route('/admin/update_phone', methods=['POST'])
def update_admin_phone():
    if 'admin' not in session:
        return jsonify({'success': False, 'error': 'Not authorized'}), 401
    
    try:
        data = request.get_json()
        phone = data.get('phone')
        
        if not phone or not phone.isdigit() or len(phone) != 10:
            return jsonify({'success': False, 'error': 'Invalid phone number format'}), 400
        
        # Update the admin's phone number in the database
        db.admins.update_one(
            {'_id': ObjectId(session['admin'])},
            {'$set': {'phone': phone}}
        )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error updating phone number: {str(e)}")
        return jsonify({'success': False, 'error': 'Error updating phone number'}), 500

@app.route('/admin/activate/<admin_id>', methods=['POST'])
@admin_required
def activate_admin(admin_id):
    try:
        # Check if the activating admin is the system admin
        admin = admins.find_one({'_id': ObjectId(session['admin'])})
        if not admin or admin.get('hospital_id') != 'ADMIN001':
            return jsonify({'success': False, 'error': 'Only system admin can activate accounts'}), 403
        
        # Update the admin's status to active
        result = admins.update_one(
            {'_id': ObjectId(admin_id)},
            {'$set': {'status': 'active'}}
        )
        
        if result.modified_count:
            # Create a notification for the activated admin
            target_admin = admins.find_one({'_id': ObjectId(admin_id)})
            if target_admin:
                notification = {
                    'admin_id': admin_id,
                    'message': f'Your account has been activated. You can now login and use the system.',
                    'type': 'system',
                    'created_at': datetime.now(pytz.UTC),
                    'read': False
                }
                notifications.insert_one(notification)
            
            return jsonify({'success': True, 'message': 'Account activated successfully'})
        else:
            return jsonify({'success': False, 'error': 'Admin not found'}), 404
            
    except Exception as e:
        print(f"Error activating admin: {str(e)}")
        return jsonify({'success': False, 'error': 'Error activating account'}), 500

@app.route('/admin/pending_admins', methods=['GET'])
@admin_required
def get_pending_admins():
    try:
        # Check if the requesting admin is the system admin
        admin = admins.find_one({'_id': ObjectId(session['admin'])})
        if not admin or admin.get('hospital_id') != 'ADMIN001':
            return jsonify({'success': False, 'error': 'Only system admin can view pending accounts'}), 403
        
        # Get all pending admin accounts
        pending_admins = list(admins.find({'status': 'pending'}))
        
        # Convert ObjectId to string for JSON serialization
        for admin in pending_admins:
            admin['_id'] = str(admin['_id'])
            
        return jsonify({
            'success': True,
            'admins': pending_admins
        })
        
    except Exception as e:
        print(f"Error fetching pending admins: {str(e)}")
        return jsonify({'success': False, 'error': 'Error fetching pending accounts'}), 500

@app.route('/admin/register_demo_fcm', methods=['POST'])
@admin_required
def register_demo_fcm():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        fcm_token = data.get('fcm_token')
        
        if not user_id or not fcm_token:
            return jsonify({'success': False, 'error': 'User ID and FCM token are required'}), 400
            
        # Update user's FCM token
        result = users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'fcm_token': fcm_token}}
        )
        
        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'FCM token registered successfully for demo purposes'
            })
        else:
            return jsonify({'success': False, 'error': 'User not found'}), 404
            
    except Exception as e:
        print(f"Error registering demo FCM token: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Add new route for handling blood donation response
@app.route('/user/respond_to_request', methods=['POST'])
def respond_to_request():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        data = request.get_json()
        request_id = data.get('request_id')
        response = data.get('response')  # 'accepted' or 'rejected'
        
        if not request_id or not response or response not in ['accepted', 'rejected']:
            return jsonify({'error': 'Invalid request parameters'}), 400
            
        # Check if user is in cooldown period
        if response == 'accepted':
            user = users.find_one({'_id': ObjectId(session['user'])})
            if user and 'last_donation_date' in user:
                last_donation = user['last_donation_date']
                if isinstance(last_donation, str):
                    last_donation = datetime.fromisoformat(last_donation.replace('Z', '+00:00'))
                cooldown_end = last_donation + timedelta(days=90)
                if datetime.now(pytz.UTC) < cooldown_end:
                    return jsonify({
                        'error': 'You are in a 90-day cooldown period after your last donation',
                        'cooldown_end': cooldown_end.strftime('%Y-%m-%d')
                    }), 400
            
        # Update notification with user's response
        result = notifications.update_one(
            {
                'request_id': request_id,
                'user_id': session['user'],
                'status': 'pending'
            },
            {
                '$set': {
                    'status': 'responded',
                    'response': response,
                    'response_time': datetime.now(pytz.UTC)
                }
            }
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Request not found or already responded'}), 404
            
        # Get notification details for response message
        notification = notifications.find_one({'request_id': request_id})
        if notification:
            # Get admin details
            admin = admins.find_one({'_id': ObjectId(notification['admin_id'])})
            if admin:
                # Send confirmation message to admin
                admin_message = f"Blood donation request {request_id} has been {response} by donor."
                try:
                    send_message_with_retry(
                        admin['phone'],
                        admin_message,
                        use_whatsapp=False
                    )
                except Exception as e:
                    print(f"Error sending confirmation to admin: {str(e)}")
        
        return jsonify({'success': True, 'message': f'Response {response} recorded successfully'})
        
    except Exception as e:
        print(f"Error processing response: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add new route for admin to select donor
@app.route('/admin/select_donor', methods=['POST'])
@admin_required
def select_donor():
    try:
        data = request.get_json()
        request_id = data.get('request_id')
        selected_user_id = data.get('user_id')
        
        if not request_id or not selected_user_id:
            return jsonify({'error': 'Missing required parameters'}), 400
            
        # Get all accepted requests for this blood request
        accepted_requests = list(notifications.find({
            'request_id': request_id,
            'status': 'responded',
            'response': 'accepted'
        }))
        
        if not accepted_requests:
            return jsonify({'error': 'No accepted requests found'}), 404
            
        # Update selected donor's status
        selected_result = notifications.update_one(
            {
                'request_id': request_id,
                'user_id': selected_user_id,
                'status': 'responded',
                'response': 'accepted'
            },
            {
                '$set': {
                    'status': 'selected',
                    'selection_time': datetime.now(pytz.UTC)
                }
            }
        )
        
        if selected_result.modified_count == 0:
            return jsonify({'error': 'Selected donor not found'}), 404
            
        # Get donor and admin details
        donor = users.find_one({'_id': ObjectId(selected_user_id)})
        admin = admins.find_one({'_id': ObjectId(session['admin'])})
        
        if not donor or not admin:
            return jsonify({'error': 'Donor or admin not found'}), 404
            
        # Store donation history
        donation_date = datetime.now(pytz.UTC)
        cooldown_end = donation_date + timedelta(days=90)
        
        donation_record = {
            'user_id': str(donor['_id']),
            'donor_name': donor['name'],
            'donor_blood_group': donor['blood_group'],
            'donor_phone': donor.get('phone', 'N/A'),
            'donor_email': donor['email'],
            'admin_id': str(admin['_id']),
            'hospital_name': admin['hospital_name'],
            'hospital_id': admin['hospital_id'],
            'donation_date': donation_date,
            'cooldown_end': cooldown_end,
            'request_id': request_id,
            'status': 'completed',
            'created_at': datetime.now(pytz.UTC)
        }
        
        donation_history.insert_one(donation_record)
            
        # Update user's last donation date and set cooldown
        users.update_one(
            {'_id': ObjectId(selected_user_id)},
            {
                '$set': {
                    'last_donation_date': donation_date,
                    'cooldown_end': cooldown_end
                }
            }
        )
        
        # Update other accepted requests to rejected
        notifications.update_many(
            {
                'request_id': request_id,
                'status': 'responded',
                'response': 'accepted',
                'user_id': {'$ne': selected_user_id}
            },
            {
                '$set': {
                    'status': 'rejected',
                    'rejection_reason': 'Another donor was selected',
                    'rejection_time': datetime.now(pytz.UTC)
                }
            }
        )
        
        # Send notification to selected donor
        donor_message = f"""Congratulations! You have been selected for blood donation.
Please contact the hospital for further details.

Note: You will be in a 90-day cooldown period after donation.
Your next donation will be possible after {cooldown_end.strftime('%Y-%m-%d')}."""
        try:
            send_message_with_retry(
                donor['phone'],
                donor_message,
                use_whatsapp=False
            )
        except Exception as e:
            print(f"Error sending notification to selected donor: {str(e)}")
        
        return jsonify({
            'success': True,
            'message': 'Donor selected successfully'
        })
        
    except Exception as e:
        print(f"Error selecting donor: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add new route to get accepted donors for a request
@app.route('/admin/accepted_donors/<request_id>', methods=['GET'])
@admin_required
def get_accepted_donors(request_id):
    try:
        # Get all accepted requests for this blood request
        accepted_requests = list(notifications.find({
            'request_id': request_id,
            'status': 'responded',
            'response': 'accepted'
        }))
        
        # Get donor details for each accepted request
        donors = []
        for request in accepted_requests:
            donor = users.find_one({'_id': ObjectId(request['user_id'])})
            if donor:
                donors.append({
                    'user_id': str(donor['_id']),
                    'name': donor['name'],
                    'blood_group': donor['blood_group'],
                    'phone': donor.get('phone', 'N/A'),
                    'email': donor['email'],
                    'response_time': request['response_time'].strftime('%Y-%m-%d %H:%M:%S'),
                    'distance': request.get('data', {}).get('distance', 'N/A')
                })
        
        return jsonify({
            'success': True,
            'donors': donors
        })
        
    except Exception as e:
        print(f"Error getting accepted donors: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Update the request stats route to include selection status
@app.route('/admin/request_stats', methods=['GET'])
@admin_required
def get_request_stats():
    try:
        admin_id = session['admin']
        
        # Get all requests sent by this admin
        requests = list(notifications.find({
            'admin_id': admin_id,
            'type': 'blood_request'
        }))
        
        # Calculate statistics
        total_requests = len(requests)
        pending_requests = len([r for r in requests if r['status'] == 'pending'])
        accepted_requests = len([r for r in requests if r['status'] == 'responded' and r['response'] == 'accepted'])
        rejected_requests = len([r for r in requests if r['status'] == 'responded' and r['response'] == 'rejected'])
        selected_donors = len([r for r in requests if r['status'] == 'selected'])
        
        # Get detailed request information
        request_details = []
        for req in requests:
            donor = users.find_one({'_id': ObjectId(req['user_id'])})
            if donor:
                request_details.append({
                    'request_id': req['request_id'],
                    'donor_name': donor['name'],
                    'blood_group': donor['blood_group'],
                    'status': req['status'],
                    'response': req.get('response'),
                    'created_at': req['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
                    'response_time': req.get('response_time').strftime('%Y-%m-%d %H:%M:%S') if req.get('response_time') else None,
                    'selection_time': req.get('selection_time').strftime('%Y-%m-%d %H:%M:%S') if req.get('selection_time') else None,
                    'rejection_reason': req.get('rejection_reason'),
                    'rejection_time': req.get('rejection_time').strftime('%Y-%m-%d %H:%M:%S') if req.get('rejection_time') else None
                })
        
        return jsonify({
            'success': True,
            'stats': {
                'total_requests': total_requests,
                'pending_requests': pending_requests,
                'accepted_requests': accepted_requests,
                'rejected_requests': rejected_requests,
                'selected_donors': selected_donors
            },
            'request_details': request_details
        })
        
    except Exception as e:
        print(f"Error getting request stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add new route to get pending blood requests for user
@app.route('/user/pending_requests', methods=['GET'])
def get_pending_requests():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        # Get all pending blood requests for the user
        pending_requests = list(notifications.find({
            'user_id': session['user'],
            'type': 'blood_request',
            'status': 'pending'
        }).sort('created_at', -1))
        
        # Get admin details for each request
        for request in pending_requests:
            admin = admins.find_one({'_id': ObjectId(request['admin_id'])})
            if admin:
                request['admin_details'] = {
                    'name': admin.get('hospital_name', 'Hospital'),
                    'address': admin.get('address', 'Address not available'),
                    'phone': admin.get('phone', 'N/A'),
                    'hospital_id': admin.get('hospital_id', 'N/A')
                }
            
            # Convert ObjectId to string for JSON serialization
            request['_id'] = str(request['_id'])
            request['created_at'] = request['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify({
            'success': True,
            'requests': pending_requests
        })
        
    except Exception as e:
        print(f"Error getting pending requests: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add new route to get user's blood request history
@app.route('/user/request_history', methods=['GET'])
def get_request_history():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        # Get all blood requests for the user (both pending and responded)
        all_requests = list(notifications.find({
            'user_id': session['user'],
            'type': 'blood_request'
        }).sort('created_at', -1))
        
        # Get admin details for each request
        for request in all_requests:
            try:
                # Check if admin_id exists and is valid
                if 'admin_id' in request and request['admin_id']:
                    admin = admins.find_one({'_id': ObjectId(request['admin_id'])})
                    if admin:
                        request['admin_details'] = {
                            'name': admin.get('hospital_name', 'Hospital'),
                            'address': admin.get('address', 'Address not available'),
                            'phone': admin.get('phone', 'N/A'),
                            'hospital_id': admin.get('hospital_id', 'N/A')
                        }
                    else:
                        request['admin_details'] = {
                            'name': 'Unknown Hospital',
                            'address': 'Address not available',
                            'phone': 'N/A',
                            'hospital_id': 'N/A'
                        }
                else:
                    request['admin_details'] = {
                        'name': 'Unknown Hospital',
                        'address': 'Address not available',
                        'phone': 'N/A',
                        'hospital_id': 'N/A'
                    }
                
                # Convert ObjectId to string and format dates for JSON serialization
                request['_id'] = str(request['_id'])
                request['created_at'] = request['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                if request.get('response_time'):
                    request['response_time'] = request['response_time'].strftime('%Y-%m-%d %H:%M:%S')
                
            except Exception as e:
                print(f"Error processing request {request.get('_id')}: {str(e)}")
                request['admin_details'] = {
                    'name': 'Unknown Hospital',
                    'address': 'Address not available',
                    'phone': 'N/A',
                    'hospital_id': 'N/A'
                }
                continue
        
        return jsonify({
            'success': True,
            'requests': all_requests
        })
        
    except Exception as e:
        print(f"Error getting request history: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/acceptance')
@admin_required
def admin_acceptance():
    return render_template('admin_acceptance.html')

@app.route('/admin/donation_history')
@admin_required
def admin_donation_history():
    return render_template('admin_donation_history.html')

@app.route('/admin/donation_history/data', methods=['GET'])
@admin_required
def get_donation_history():
    try:
        # Get query parameters
        status = request.args.get('status')
        blood_group = request.args.get('blood_group')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Build query
        query = {}
        if status:
            query['status'] = status
        if blood_group:
            query['donor_blood_group'] = blood_group
        if start_date:
            query['donation_date'] = {'$gte': datetime.fromisoformat(start_date.replace('Z', '+00:00'))}
        if end_date:
            if 'donation_date' in query:
                query['donation_date']['$lte'] = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            else:
                query['donation_date'] = {'$lte': datetime.fromisoformat(end_date.replace('Z', '+00:00'))}
        
        # Get donation history
        donations = list(donation_history.find(query).sort('donation_date', -1))
        
        # Convert ObjectId to string and format dates
        for donation in donations:
            donation['_id'] = str(donation['_id'])
            donation['donation_date'] = donation['donation_date'].strftime('%Y-%m-%d %H:%M:%S')
            donation['cooldown_end'] = donation['cooldown_end'].strftime('%Y-%m-%d %H:%M:%S')
            donation['created_at'] = donation['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Calculate days remaining in cooldown
            cooldown_end = datetime.fromisoformat(donation['cooldown_end'].replace('Z', '+00:00'))
            days_remaining = (cooldown_end - datetime.now(pytz.UTC)).days
            donation['days_remaining'] = max(0, days_remaining)
            donation['cooldown_status'] = 'Active' if days_remaining > 0 else 'Completed'
        
        return jsonify({
            'success': True,
            'donations': donations
        })
        
    except Exception as e:
        print(f"Error getting donation history: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/donation_history/stats', methods=['GET'])
@admin_required
def get_donation_stats():
    try:
        # Get total donations
        total_donations = donation_history.count_documents({})
        
        # Get donations by blood group
        blood_group_stats = list(donation_history.aggregate([
            {'$group': {'_id': '$donor_blood_group', 'count': {'$sum': 1}}}
        ]))
        
        # Get active cooldowns
        active_cooldowns = donation_history.count_documents({
            'cooldown_end': {'$gt': datetime.now(pytz.UTC)}
        })
        
        # Get donations by hospital
        hospital_stats = list(donation_history.aggregate([
            {'$group': {'_id': '$hospital_name', 'count': {'$sum': 1}}}
        ]))
        
        return jsonify({
            'success': True,
            'stats': {
                'total_donations': total_donations,
                'blood_group_stats': blood_group_stats,
                'active_cooldowns': active_cooldowns,
                'hospital_stats': hospital_stats
            }
        })
        
    except Exception as e:
        print(f"Error getting donation stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

def is_eligible_for_donation(user):
    """
    Check if a user is eligible for blood donation based on their stored data
    """
    try:
        # Check age
        if not (18 <= user.get('age', 0) <= 65):
            return False, "Age must be between 18 and 65 years"
        
        # Check weight
        if user.get('weight', 0) < 45:
            return False, "Minimum weight required is 45 kg for blood donation"
        
        # Check height
        if not (140 <= user.get('height', 0) <= 220):
            return False, "Height must be between 140 and 220 cm"
        
        # Check last donation date
        last_donation = user.get('last_donation_date')
        if last_donation:
            if isinstance(last_donation, str):
                last_donation = datetime.strptime(last_donation, '%Y-%m-%d')
            today = datetime.now()
            four_months_ago = today - timedelta(days=120)
            
            if last_donation > today:
                return False, "Last donation date cannot be in the future"
            if last_donation > four_months_ago:
                return False, "You cannot donate if your last donation was less than 4 months ago"
        
        return True, "Eligible for donation"
    except Exception as e:
        logger.error(f"Error checking donation eligibility: {str(e)}")
        return False, "Error checking eligibility"

def get_eligible_donors(blood_group=None, max_distance=None, admin_location=None):
    """
    Get list of eligible donors based on criteria
    """
    try:
        query = {}
        if blood_group:
            query['blood_group'] = blood_group
        
        # Get all matching donors
        donors = list(users.find(query))
        eligible_donors = []
        
        for donor in donors:
            # Check eligibility
            is_eligible, message = is_eligible_for_donation(donor)
            if not is_eligible:
                continue
            
            # Check distance if admin location is provided
            if max_distance and admin_location:
                donor_location = donor.get('location', {}).get('coordinates', [0, 0])
                distance = haversine_distance(
                    admin_location['lat'], admin_location['lon'],
                    donor_location[1], donor_location[0]
                )
                if distance > max_distance:
                    continue
            
            # Add donor to eligible list
            eligible_donors.append({
                'id': str(donor['_id']),
                'name': donor['name'],
                'blood_group': donor['blood_group'],
                'age': donor['age'],
                'gender': donor['gender'],
                'weight': donor['weight'],
                'height': donor['height'],
                'phone': donor.get('phone', 'N/A'),
                'email': donor['email'],
                'last_donation_date': donor.get('last_donation_date'),
                'location': donor.get('location', {}).get('address', 'Address not available')
            })
        
        return eligible_donors
        
    except Exception as e:
        logger.error(f"Error getting eligible donors: {str(e)}")
        return []

def update_user_health_data(user_id, data):
    """
    Update user's health-related data
    """
    try:
        update_data = {}
        
        # Validate and update age
        if 'age' in data:
            age = int(data['age'])
            if 18 <= age <= 65:
                update_data['age'] = age
            else:
                return False, "Age must be between 18 and 65 years"
        
        # Update gender
        if 'gender' in data:
            if data['gender'] in ['male', 'female', 'other']:
                update_data['gender'] = data['gender']
            else:
                return False, "Invalid gender value"
        
        # Validate and update height
        if 'height' in data:
            height = float(data['height'])
            if 140 <= height <= 220:
                update_data['height'] = height
            else:
                return False, "Height must be between 140 and 220 cm"
        
        # Validate and update weight
        if 'weight' in data:
            weight = float(data['weight'])
            if weight >= 45:
                update_data['weight'] = weight
            else:
                return False, "Minimum weight required is 45 kg"
        
        # Update last donation date
        if 'last_donation_date' in data:
            try:
                last_donation = datetime.strptime(data['last_donation_date'], '%Y-%m-%d')
                today = datetime.now()
                if last_donation <= today:
                    update_data['last_donation_date'] = data['last_donation_date']
                else:
                    return False, "Last donation date cannot be in the future"
            except ValueError:
                return False, "Invalid date format"
        
        if update_data:
            result = users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': update_data}
            )
            if result.modified_count > 0:
                return True, "Health data updated successfully"
            else:
                return False, "User not found"
        
        return False, "No valid data to update"
        
    except Exception as e:
        logger.error(f"Error updating user health data: {str(e)}")
        return False, "Error updating health data"

@app.route('/user/update_health_data', methods=['POST'])
def update_health_data():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        data = request.get_json()
        user_id = session['user']
        
        success, message = update_user_health_data(user_id, data)
        if success:
            return jsonify({'message': message}), 200
        else:
            return jsonify({'error': message}), 400
            
    except Exception as e:
        logger.error(f"Error updating health data: {str(e)}")
        return jsonify({'error': 'An error occurred while updating health data'}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data = request.get_json()
        message = data.get('message', '').lower().strip()
        language = data.get('language', 'en')
        
        if not message:
            return jsonify({'error': 'No message provided'}), 400

        # Define responses for different types of questions
        responses = {
            'eligibility': """Eligibility Requirements:
• Age: 18-65 years
• Weight: Minimum 45 kg
• Good health condition
• No recent infections
• Valid ID required""",
            
            'benefits': """Benefits of Donation:
• Saves up to 3 lives
• Free health screening
• Reduces heart disease risk
• Helps maintain iron levels
• Feel good helping others""",
            
            'preparation': """Preparation Tips:
• Get good sleep
• Eat a healthy meal
• Drink plenty of water
• Wear comfortable clothes
• Bring ID""",
            
            'process': """Donation Process:
• Quick health check
• Mini physical exam
• 8-10 minutes donation
• Rest and refreshments
• Total time: 45 minutes""",
            
            'frequency': """Donation Frequency:
• Whole blood: Every 56 days
• Platelets: Every 7 days
• Plasma: Every 28 days
• Double red cells: Every 112 days""",
            
            'general': """General Information:
• Blood donation saves lives
• Process is safe and easy
• Takes about 45 minutes
• All blood types needed
• Contact blood bank for details"""
        }
        
        # Check message content and return appropriate response
        response = None
        
        # Define keywords for each category
        keywords = {
            'eligibility': ['eligible', 'qualify', 'can i donate', 'requirements', 'criteria'],
            'benefits': ['benefit', 'advantage', 'why donate', 'help', 'good'],
            'preparation': ['prepare', 'before donation', 'how to', 'ready', 'tips'],
            'process': ['process', 'procedure', 'what happens', 'during', 'step'],
            'frequency': ['how often', 'frequency', 'when again', 'wait', 'period']
        }
        
        # Check message against keywords
        for category, words in keywords.items():
            if any(word in message for word in words):
                response = responses[category]
                break
        
        # If no specific match found, return general information
        if not response:
            response = responses['general']
        
        # Translate if needed
        if language != 'en':
            try:
                response = translate_text(response, language)
            except Exception as e:
                print(f"Translation error: {str(e)}")
                # Keep English response if translation fails
        
        return jsonify({
            'success': True,
            'response': response
        })
        
    except Exception as e:
        print(f"Chat API error: {str(e)}")
        return jsonify({
            'success': True,
            'response': 'Please try again or contact the blood bank directly for assistance.'
        }), 200

@app.route('/profile')
def profile():
    if 'user' not in session:
        flash(get_translations(session.get('language', 'en'))['login_required'])
        return redirect(url_for('login'))
        
    language = session.get('language', 'en')
    translations = get_translations(language)
    
    user_id = session['user']
    user = users.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        session.pop('user', None)
        flash(translations['error_message'])
        return redirect(url_for('login'))
    
    return render_template('profile.html',
                         user=user,
                         translations=translations)

@app.route('/user/update_profile', methods=['POST'])
def update_user_profile():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        user_id = session['user']
        data = request.form
        
        # Validate data
        if not data.get('name') or not data.get('phone') or not data.get('age') or not data.get('height') or not data.get('weight') or not data.get('gender'):
            return jsonify({'error': 'All fields are required'}), 400
            
        # Update user profile
        update_data = {
            'name': data.get('name'),
            'phone': data.get('phone'),
            'age': int(data.get('age')),
            'height': float(data.get('height')),
            'weight': float(data.get('weight')),
            'gender': data.get('gender')
        }
        
        result = users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'No changes made'}), 400
            
    except Exception as e:
        print(f"Error updating profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/user/update_avatar', methods=['POST'])
def update_avatar():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        if 'avatar' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
            
        file = request.files['avatar']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if file and allowed_file(file.filename):
            # Generate unique filename
            filename = secure_filename(f"avatar_{session['user']}_{file.filename}")
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Save file
            file.save(file_path)
            
            # Update user's avatar in database
            result = users.update_one(
                {'_id': ObjectId(session['user'])},
                {'$set': {'avatar': filename}}
            )
            
            if result.modified_count > 0:
                return jsonify({
                    'success': True,
                    'avatar_url': url_for('static', filename=f'uploads/{filename}')
                })
            else:
                return jsonify({'error': 'Failed to update avatar'}), 500
        else:
            return jsonify({'error': 'Invalid file type'}), 400
            
    except Exception as e:
        print(f"Error updating avatar: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/user/update_location', methods=['POST'])
def update_location():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        data = request.get_json()
        user_id = session['user']
        
        if not data.get('latitude') or not data.get('longitude') or not data.get('address'):
            return jsonify({'error': 'Missing location data'}), 400
            
        # Update user's location
        update_data = {
            'location': {
                'type': 'Point',
                'coordinates': [float(data['longitude']), float(data['latitude'])],
                'address': data['address']
            }
        }
        
        result = users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': update_data}
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Failed to update location'}), 500
            
    except Exception as e:
        print(f"Error updating location: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/user/stats')
def get_user_stats():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        user_id = session['user']
        user = users.find_one({'_id': ObjectId(user_id)})
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        # Get donation history
        donations = list(donation_history.find({'user_id': user_id}).sort('donation_date', -1))
        
        # Calculate stats
        total_donations = len(donations)
        last_donation = donations[0]['donation_date'].strftime('%Y-%m-%d') if donations else None
        
        # Calculate next eligible date
        next_eligible = None
        if last_donation:
            last_donation_date = donations[0]['donation_date']
            next_eligible_date = last_donation_date + timedelta(days=90)
            if datetime.now(pytz.UTC) < next_eligible_date:
                next_eligible = next_eligible_date.strftime('%Y-%m-%d')
            else:
                next_eligible = 'Now'
        
        return jsonify({
            'success': True,
            'stats': {
                'total_donations': total_donations,
                'last_donation': last_donation,
                'next_eligible': next_eligible
            }
        })
        
    except Exception as e:
        print(f"Error getting user stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/user/upcoming_camps')
def get_upcoming_camps():
    if 'user' not in session:
        return jsonify({'error': 'Not authorized'}), 401
        
    try:
        # Get user's location
        user = users.find_one({'_id': ObjectId(session['user'])})
        if not user or 'location' not in user:
            return jsonify({'error': 'User location not found'}), 404
            
        user_lat = user['location']['coordinates'][1]
        user_lng = user['location']['coordinates'][0]
        
        # Get all blood camps within 10km
        camps = []
        for admin in admins.find():
            if 'location' not in admin:
                continue
                
            admin_lat = admin['location']['coordinates'][1]
            admin_lon = admin['location']['coordinates'][0]
            
            # Calculate distance
            distance = haversine_distance(user_lat, user_lng, admin_lat, admin_lon)
            
            if distance <= 10:  # Within 10km
                camps.append({
                    'name': admin['hospital_name'],
                    'date': (datetime.now(pytz.UTC) + timedelta(days=7)).strftime('%Y-%m-%d'),  # Example: 7 days from now
                    'location': admin['address']
                })
        
        return jsonify({
            'success': True,
            'camps': camps
        })
        
    except Exception as e:
        print(f"Error getting upcoming camps: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.context_processor
def inject_language():
    return dict(language=session.get('language', 'en'))

# Error handlers with translations
@app.errorhandler(404)
def page_not_found(e):
    language = session.get('language', 'en')
    translations = get_translations(language)
    return render_template('errors/404.html',
                         error_title=translations['404_title'],
                         error_message=translations['404_message'],
                         translations=translations), 404

@app.errorhandler(500)
def server_error(e):
    language = session.get('language', 'en')
    translations = get_translations(language)
    return render_template('errors/500.html',
                         error_title=translations['500_title'],
                         error_message=translations['500_message'],
                         translations=translations), 500

@app.errorhandler(403)
def forbidden(e):
    language = session.get('language', 'en')
    translations = get_translations(language)
    return render_template('errors/403.html',
                         error_title=translate_text('Access Denied', language),
                         error_message=translate_text('You do not have permission to access this page', language),
                         translations=translations), 403

# Context processor to make translations available in all templates
@app.context_processor
def inject_translations():
    language = session.get('language', 'en')
    return {'translations': get_translations(language)}

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    language = session.get('language', 'en')
    translations = get_translations(language)
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        admin = admins.find_one({'email': email})
        
        if admin and admin['password'] == password:  # Using plain password as per requirements
            session['admin'] = str(admin['_id'])
            flash(translations['login_success'])
            return redirect(url_for('admin_dashboard'))
        else:
            flash(translations['invalid_credentials'])
    
    return render_template('admin_login.html', translations=translations)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    language = session.get('language', 'en')
    translations = get_translations(language)
    
    try:
        admin = admins.find_one({'_id': ObjectId(session['admin'])})
        if not admin:
            session.pop('admin', None)
            flash(translations['error_message'])
            return redirect(url_for('admin_login'))
            
        # Get admin's hospital location
        admin_location = admin.get('location', {}).get('coordinates', [0, 0])
        
        # Get nearby donors (within 10km)
        nearby_donors = list(users.find({
            'location': {
                '$near': {
                    '$geometry': {
                        'type': 'Point',
                        'coordinates': admin_location
                    },
                    '$maxDistance': 10000  # 10km in meters
                }
            }
        }).limit(5))
        
        # Get recent donation history
        recent_donations = list(donation_history.find().sort('donation_date', -1).limit(5))
        
        # Get pending blood requests
        pending_requests = list(notifications.find({
            'type': 'blood_request',
            'status': 'pending'
        }).sort('created_at', -1).limit(5))
        
        return render_template('admin_dashboard.html',
                             admin=admin,
                             nearby_donors=nearby_donors,
                             recent_donations=recent_donations,
                             pending_requests=pending_requests,
                             translations=translations)
                             
    except Exception as e:
        print(f"Error in admin dashboard: {str(e)}")
        flash(translations['error_message'])
        return redirect(url_for('admin_login'))

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    language = session.get('language', 'en')
    translations = get_translations(language)
    
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        hospital_name = request.form.get('hospital_name')
        hospital_id = request.form.get('hospital_id')  # New field
        phone = request.form.get('phone')
        location = request.form.get('location')
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        # Validate hospital ID format (e.g., HOSP001)
        if not hospital_id or not hospital_id.startswith('HOSP'):
            flash('Invalid hospital ID format. Must start with HOSP followed by numbers')
            return render_template('admin_signup.html', translations=translations)
            
        if admins.find_one({'email': email}):
            flash(translations['email_exists'])
            return render_template('admin_signup.html', translations=translations)
            
        if admins.find_one({'hospital_id': hospital_id}):
            flash('Hospital ID already exists')
            return render_template('admin_signup.html', translations=translations)
            
        new_admin = {
            'name': name,
            'email': email,
            'password': password,  # Using plain password as per requirements
            'hospital_name': hospital_name,
            'hospital_id': hospital_id,
            'phone': phone,
            'location': {
                'type': 'Point',
                'coordinates': [float(longitude), float(latitude)],
                'address': location
            },
            'status': 'pending',  # Set initial status as pending
            'created_at': datetime.utcnow()
        }
        
        admins.insert_one(new_admin)
        flash(translations['registration_success'])
        return redirect(url_for('admin_login'))
        
    return render_template('admin_signup.html', translations=translations)

# Add routes for notice card management
@app.route('/admin/create_notice', methods=['POST'])
@admin_required
def create_notice():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['title', 'organization_type', 'organization_name', 'description', 
                         'contact_person', 'contact_number', 'email', 'address']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'success': False, 'error': f'{field} is required'})
        
        # Create notice document
        notice = {
            'title': data['title'],
            'organization_type': data['organization_type'],
            'organization_name': data['organization_name'],
            'description': data['description'],
            'contact_person': data['contact_person'],
            'contact_number': data['contact_number'],
            'email': data['email'],
            'address': data['address'],
            'event_date': data.get('event_date'),
            'requirements': data.get('requirements', []),
            'blood_groups_needed': data.get('blood_groups_needed', []),
            'image_url': data.get('image_url'),
            'latitude': data.get('latitude'),
            'longitude': data.get('longitude'),
            'location': data.get('location'),
            'created_at': datetime.utcnow(),
            'created_by': session['admin'],  # Changed from user_id to admin
            'status': 'active'
        }
        
        # Insert notice into database
        db.notice_cards.insert_one(notice)
        
        # Send notifications to all users
        users = db.users.find({})
        notification_text = f"New {notice['organization_type']} notice: {notice['title']} by {notice['organization_name']}"
        
        for user in users:
            notification = {
                'user_id': user['_id'],
                'message': notification_text,
                'notice_id': notice['_id'],
                'created_at': datetime.utcnow(),
                'read': False
            }
            db.notifications.insert_one(notification)
            
            # Send SMS if phone number is available
            if user.get('phone'):
                try:
                    send_sms(user['phone'], notification_text)
                except Exception as e:
                    print(f"Error sending SMS to {user['phone']}: {str(e)}")
        
        return jsonify({'success': True, 'message': 'Notice created successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/notice')
@admin_required
def admin_notice():
    return render_template('admin_notice.html')

@app.route('/admin/notices')
@admin_required
def get_notices():
    try:
        notices = list(db.notice_cards.find({'created_by': session['admin']}).sort('created_at', -1))
        
        # Convert ObjectId to string for JSON serialization
        for notice in notices:
            notice['_id'] = str(notice['_id'])
            notice['created_by'] = str(notice['created_by'])
        
        return jsonify({'success': True, 'notices': notices})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/notice/<notice_id>', methods=['DELETE'])
@admin_required
def delete_notice(notice_id):
    try:
        # Verify ownership
        notice = db.notice_cards.find_one({'_id': ObjectId(notice_id), 'created_by': session['admin']})
        if not notice:
            return jsonify({'success': False, 'error': 'Notice not found or unauthorized'})
        
        # Delete notice
        db.notice_cards.delete_one({'_id': ObjectId(notice_id)})
        
        # Delete related notifications
        db.notifications.delete_many({'notice_id': ObjectId(notice_id)})
        
        return jsonify({'success': True, 'message': 'Notice deleted successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/notice/<notice_id>', methods=['PUT'])
@admin_required
def update_notice_status(notice_id):
    try:
        data = request.get_json()
        
        # Verify ownership
        notice = db.notice_cards.find_one({'_id': ObjectId(notice_id), 'created_by': session['admin']})
        if not notice:
            return jsonify({'success': False, 'error': 'Notice not found or unauthorized'})
        
        # Update status
        db.notice_cards.update_one(
            {'_id': ObjectId(notice_id)},
            {'$set': {'status': data['status']}}
        )
        
        return jsonify({'success': True, 'message': 'Notice status updated successfully'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def calculate_distance(lat1, lon1, lat2, lon2):
    """
    Calculate the distance between two points using the Haversine formula.
    Returns distance in kilometers.
    """
    R = 6371  # Earth's radius in kilometers

    lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    
    # Convert latitude and longitude to radians
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    
    # Calculate distance in kilometers
    distance = R * c
    return round(distance, 2)

# User-facing notice routes
@app.route('/notices')
@login_required
def user_notices():
    try:
        # Get active notices
        notices = list(db.notice_cards.find({'status': 'active'}).sort('created_at', -1))
        
        # Convert ObjectId to string and add distance calculation
        for notice in notices:
            notice['_id'] = str(notice['_id'])
            notice['created_by'] = str(notice['created_by'])
            
            # Add distance calculation if user location is available
            if 'location' in session and notice.get('latitude') and notice.get('longitude'):
                user_lat = float(session['location']['latitude'])
                user_lng = float(session['location']['longitude'])
                notice['distance'] = calculate_distance(
                    user_lat, user_lng,
                    float(notice['latitude']), float(notice['longitude'])
                )
        
        # Render template instead of returning JSON
        return render_template('user_notices.html', notices=notices)
    
    except Exception as e:
        flash('Error loading notices: ' + str(e))
        return redirect(url_for('dashboard'))

# Add API endpoint for getting notices data
@app.route('/api/notices')
@login_required
def get_notices_api():
    try:
        notices = list(db.notice_cards.find({'status': 'active'}).sort('created_at', -1))
        
        for notice in notices:
            notice['_id'] = str(notice['_id'])
            notice['created_by'] = str(notice['created_by'])
            
            if 'location' in session and notice.get('latitude') and notice.get('longitude'):
                user_lat = float(session['location']['latitude'])
                user_lng = float(session['location']['longitude'])
                notice['distance'] = calculate_distance(
                    user_lat, user_lng,
                    float(notice['latitude']), float(notice['longitude'])
                )
        
        return jsonify({'success': True, 'notices': notices})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Mobile API Routes
@app.route('/api/mobile/login', methods=['POST'])
def mobile_login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({'message': 'Email and password are required'}), 400

        email = data['email']
        password = data['password']

        # Find user by email
        user = users.find_one({'email': email})
        if not user:
            return jsonify({'message': 'Invalid email or password'}), 401

        # Verify password
        if not check_password_hash(user['password'], password):
            return jsonify({'message': 'Invalid email or password'}), 401

        # Generate token
        token = generate_token(str(user['_id']))

        # Update session
        session['user'] = str(user['_id'])
        session['user_name'] = user['name']
        session['user_email'] = user['email']

        # Return user data and token
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email'],
                'blood_group': user.get('blood_group'),
                'phone': user.get('phone'),
                'location': user.get('location', {})
            }
        }), 200

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

@app.route('/api/mobile/profile', methods=['GET'])
@mobile_auth_required
def mobile_profile():
    try:
        # Get user from request context (set by decorator)
        user_id = g.user_id
        
        # Find user in database
        try:
            user = users.find_one({'_id': ObjectId(user_id)})
        except Exception as e:
            logger.error(f"Error finding user: {str(e)}")
            return jsonify({'message': 'Invalid user ID format'}), 400
            
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Get user's location
        location = user.get('location', {})
        
        # Return user data
        return jsonify({
            'user': {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email'],
                'blood_group': user.get('blood_group'),
                'phone': user.get('phone'),
                'location': {
                    'address': location.get('address'),
                    'latitude': location.get('latitude'),
                    'longitude': location.get('longitude')
                },
                'last_donation': user.get('last_donation'),
                'cooldown_end': user.get('cooldown_end')
            }
        }), 200

    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        return jsonify({'message': 'Failed to get profile', 'error': str(e)}), 500

@app.route('/api/mobile/notifications', methods=['GET'])
@mobile_auth_required
def mobile_notifications():
    try:
        user_notifications = list(notifications.find(
            {'user_id': g.user_id}
        ).sort('created_at', -1))
        
        # Convert ObjectId to string and format dates
        for notif in user_notifications:
            notif['_id'] = str(notif['_id'])
            notif['created_at'] = notif['created_at'].strftime('%Y-%m-%d %H:%M:%S')
            
        return jsonify({
            'success': True,
            'notifications': user_notifications
        })
        
    except Exception as e:
        logger.error(f"Notifications error: {str(e)}")
        return jsonify({'message': 'Failed to get notifications', 'error': str(e)}), 500

@app.route('/api/mobile/update_profile', methods=['POST'])
@mobile_auth_required
def mobile_update_profile():
    try:
        # Get user from request context (set by decorator)
        user_id = g.user_id
        
        # Get update data from request
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400

        # Find user in database
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Update user data
        update_data = {}
        
        # Update name if provided
        if 'name' in data:
            update_data['name'] = data['name']
            
        # Update phone if provided
        if 'phone' in data:
            update_data['phone'] = data['phone']
            
        # Update blood group if provided
        if 'blood_group' in data:
            update_data['blood_group'] = data['blood_group']
            
        # Update location if provided
        if 'location' in data:
            location = data['location']
            if isinstance(location, dict):
                update_data['location'] = {
                    'address': location.get('address'),
                    'latitude': location.get('latitude'),
                    'longitude': location.get('longitude')
                }

        # Perform update if there are changes
        if update_data:
            users.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': update_data}
            )
            
            # Get updated user data
            updated_user = users.find_one({'_id': ObjectId(user_id)})
            location = updated_user.get('location', {})
            
            return jsonify({
                'message': 'Profile updated successfully',
                'user': {
                    'id': str(updated_user['_id']),
                    'name': updated_user['name'],
                    'email': updated_user['email'],
                    'blood_group': updated_user.get('blood_group'),
                    'phone': updated_user.get('phone'),
                    'location': {
                        'address': location.get('address'),
                        'latitude': location.get('latitude'),
                        'longitude': location.get('longitude')
                    },
                    'last_donation': updated_user.get('last_donation'),
                    'cooldown_end': updated_user.get('cooldown_end')
                }
            }), 200
        else:
            return jsonify({'message': 'No changes provided'}), 400

    except Exception as e:
        logger.error(f"Update profile error: {str(e)}")
        return jsonify({'message': 'Failed to update profile', 'error': str(e)}), 500

@app.route('/api/signup', methods=['POST'])
def mobile_signup():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'email', 'password', 'blood_group', 'phone', 
                         'location', 'latitude', 'longitude', 'age', 'height', 
                         'weight', 'gender']
        for field in required_fields:
            if field not in data:
                return jsonify({'message': f'Missing required field: {field}'}), 400
        
        # Check if user already exists
        if users.find_one({'email': data['email']}):
            return jsonify({'message': 'Email already registered'}), 400
        
        # Format location for geospatial indexing
        location_data = {
            'type': 'Point',
            'coordinates': [float(data['longitude']), float(data['latitude'])],
            'address': data['location']
        }
        
        # Create new user
        user = {
            'name': data['name'],
            'email': data['email'],
            'password': generate_password_hash(data['password']),
            'blood_group': data['blood_group'],
            'phone': data['phone'],
            'location': location_data,
            'latitude': float(data['latitude']),
            'longitude': float(data['longitude']),
            'age': int(data['age']),
            'height': float(data['height']),
            'weight': float(data['weight']),
            'gender': data['gender'],
            'last_donation': data.get('last_donation'),
            'created_at': datetime.now(pytz.UTC),
            'role': 'user',
            'is_eligible': True if not data.get('last_donation') else (
                datetime.now(pytz.UTC) - 
                datetime.strptime(data.get('last_donation'), '%Y-%m-%d').replace(tzinfo=pytz.UTC)
            ).days >= 120
        }
        
        users.insert_one(user)
        
        return jsonify({'message': 'User registered successfully'}), 201
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/admin/user/<int:user_id>')
@login_required
def get_user_info(user_id):
    if 'admin' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    user = users.find_one({'_id': ObjectId(user_id)})
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    return jsonify({
        'success': True,
        'user': {
            'name': user['name'],
            'email': user['email'],
            'phone': user['phone'],
            'blood_group': user['blood_group'],
            'last_donation_date': user.get('last_donation_date'),
            'cooldown_end': user.get('cooldown_end'),
            'location': {
                'address': user.get('location', {}).get('address'),
                'latitude': user.get('location', {}).get('coordinates', [0, 0])[1],
                'longitude': user.get('location', {}).get('coordinates', [0, 0])[0]
            }
        }
    })

if __name__ == '__main__':
    print("Starting the application...")
    print("Application started successfully")
    print("accessing the application at http://localhost:5001")
    app.run(debug=True, port=5001,host='0.0.0.0') 
    