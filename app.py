from flask import Flask
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from models import db
from resources.admin import admin_blueprint
from resources.user import user_blueprint
from itsdangerous import URLSafeSerializer

def create_app():
    app = Flask(__name__)

    # App configurations
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hotspot_system.db'  # Database URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False                  # Suppress SQLAlchemy warning
    app.config['SECRET_KEY'] = 'super-secret'                          # Flask secret key
    app.config['JWT_SECRET_KEY'] = 'super-secret'                  # JWT secret key

    # Initialize extensions
    db.init_app(app)                      # Initialize the database
    jwt = JWTManager(app)                 # Initialize JWT
    bcrypt = Bcrypt(app)                  # Initialize Bcrypt for password hashing
    app.serializer = URLSafeSerializer(app.config['SECRET_KEY'])  # Serializer for email confirmation

    # Register blueprints
    app.register_blueprint(admin_blueprint, url_prefix='/admin')
    app.register_blueprint(user_blueprint, url_prefix='/user')
   
    
    

    return app

if __name__ == '__main__':
    app = create_app()

    # Create the database tables before running the app
    with app.app_context():
        db.create_all()

    # Run the application
    app.run(debug=True)
