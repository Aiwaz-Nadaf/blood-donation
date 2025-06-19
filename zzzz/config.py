import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev')
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'uploads')
    ALLOWED_EXTENSIONS = os.getenv('ALLOWED_EXTENSIONS', 'pdf,jpg,jpeg,png').split(',')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # MongoDB configuration
    MONGODB_URI = os.getenv('MONGODB_URI')
    
    # Firebase configuration
    FIREBASE_CONFIG = {
        'apiKey': os.getenv('FIREBASE_API_KEY'),
        'authDomain': os.getenv('FIREBASE_AUTH_DOMAIN'),
        'projectId': os.getenv('FIREBASE_PROJECT_ID'),
        'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET'),
        'messagingSenderId': os.getenv('FIREBASE_MESSAGING_SENDER_ID'),
        'appId': os.getenv('FIREBASE_APP_ID'),
        'measurementId': os.getenv('FIREBASE_MEASUREMENT_ID')
    }
    FIREBASE_VAPID_KEY = os.getenv('FIREBASE_VAPID_KEY')
    
    # Rate limiting
    RATELIMIT_DEFAULT = "100 per minute"
    
    # Security
    SESSION_COOKIE_SECURE = False  # Changed to False for development
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = None  # Changed to None to fix redirect issues
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = 'app.log'

    # Add OpenAI configuration
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY') 