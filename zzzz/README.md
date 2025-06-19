# Blood Donation System

A web application for blood donation management built with Flask, MongoDB Atlas, and Bootstrap.

## Features

- User registration with blood group and location tracking
- User authentication
- Responsive design
- Real-time location tracking
- Dashboard for user information

## Prerequisites

- Python 3.7 or higher
- MongoDB Atlas account
- pip (Python package manager)

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd blood-donation-system
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Create a MongoDB Atlas account and get your connection string:
   - Go to [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
   - Create a free account
   - Create a new cluster
   - Get your connection string

5. Update the `.env` file:
   - Replace `your_mongodb_atlas_connection_string_here` with your actual MongoDB Atlas connection string

## Running the Application

1. Make sure your virtual environment is activated

2. Run the Flask application:
```bash
python app.py
```

3. Open your web browser and navigate to:
```
http://localhost:5000
```

## Project Structure

```
blood-donation-system/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── .env               # Environment variables
├── static/            # Static files (CSS, JS)
│   └── style.css
└── templates/         # HTML templates
    ├── base.html
    ├── landing.html
    ├── login.html
    ├── signup.html
    └── dashboard.html
```

## Security Notes

- The application uses session-based authentication
- Passwords are stored in plain text (for demo purposes only)
- In a production environment, you should:
  - Hash passwords using bcrypt or similar
  - Use HTTPS
  - Implement proper session management
  - Add input validation and sanitization
  - Use environment variables for sensitive data

## Contributing

Feel free to submit issues and enhancement requests! 