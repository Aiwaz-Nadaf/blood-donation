from functools import wraps
from flask import request, jsonify, session, current_app, g
import jwt
from datetime import datetime, timedelta
import os
from bson import ObjectId
import logging
from pymongo import MongoClient

logger = logging.getLogger(__name__)

# MongoDB configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://donate-blood:jspmdonate@cluster0.evglf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
DB_NAME = os.getenv('DB_NAME', 'blood_donation')

# Create MongoDB client
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users = db.users

# JWT configuration
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DELTA = timedelta(days=7)

def generate_token(user_id):
    """Generate a JWT token for the user."""
    try:
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(days=1)
        }
        token = jwt.encode(payload, os.getenv('SECRET_KEY', 'your-secret-key'), algorithm='HS256')
        return token
    except Exception as e:
        logger.error(f"Error generating token: {str(e)}")
        raise

def verify_token(token):
    """Verify a JWT token and return the user ID if valid."""
    try:
        payload = jwt.decode(token, os.getenv('SECRET_KEY', 'your-secret-key'), algorithms=['HS256'])
        return str(payload['user_id'])  # Ensure we return a string
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error verifying token: {str(e)}")
        return None

def mobile_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            # Get token from header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                logger.warning("No Authorization header found")
                return jsonify({'message': 'Missing token'}), 401

            # Extract token
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                logger.warning("Invalid Authorization header format")
                return jsonify({'message': 'Invalid token format'}), 401

            # Verify token
            user_id = verify_token(token)
            if not user_id:
                logger.warning("Token verification failed")
                return jsonify({'message': 'Invalid or expired token'}), 401

            # Get user from database
            try:
                user = users.find_one({'_id': ObjectId(user_id)})
            except Exception as e:
                logger.error(f"Error finding user: {str(e)}")
                return jsonify({'message': 'Invalid user ID format'}), 400
                
            if not user:
                logger.warning(f"User not found for id: {user_id}")
                return jsonify({'message': 'User not found'}), 404

            # Set user info in Flask's g object
            g.user_id = user_id
            g.user = user

            # Update session
            session['user'] = user_id
            session['user_name'] = user['name']
            session['user_email'] = user['email']

            logger.info(f"Successfully authenticated user: {user_id}")
            return f(*args, **kwargs)

        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return jsonify({'message': 'Authentication failed', 'error': str(e)}), 500

    return decorated
