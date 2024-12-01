from functools import wraps
from flask import Blueprint
from flask_restful import Resource, reqparse, fields, marshal_with, Api
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    create_access_token,
    create_refresh_token
)
from flask_bcrypt import generate_password_hash, check_password_hash
from models import db, Admin, User, Bonus, Hotspot, Payment
from datetime import datetime
from sqlalchemy.exc import IntegrityError

# Admin Blueprint
admin_blueprint = Blueprint('admin', __name__)

# Field definitions
user_fields = {
    'user_id': fields.Integer,
    'phone_number': fields.String,
    'subscription': fields.String,
    'expiry_time': fields.String,
    'hotspot_id': fields.Integer
}

bonus_fields = {
    'bonus_id': fields.Integer,
    'admin_id': fields.Integer,
    'user_id': fields.Integer,
    'duration': fields.Integer
}

# Hotspot Fields
hotspot_fields = {
    'hotspot_id': fields.Integer,
    'hotspot_name': fields.String,
    'router_mac': fields.String,
    'admin_id': fields.Integer
}

hotspot_response_field = {
    "message": fields.String,
    "status": fields.String,
    "hotspots": fields.List(fields.Nested(hotspot_fields))
}

# Payment Fields
payment_fields = {
    'payment_id': fields.Integer,
    'user_id': fields.Integer,
    'amount': fields.Float,
    'hotspot_id': fields.Integer,
    'timestamp': fields.String
}

payment_response_field = {
    "message": fields.String,
    "status": fields.String,
    "payments": fields.List(fields.Nested(payment_fields))
}




admin_fields = {
    'admin_id': fields.Integer,
    'name': fields.String,
    'email': fields.String
}

auth_response_field = {
    "message": fields.String,
    "status": fields.String,
    "admins": fields.List(fields.Nested(admin_fields)),
    "access_token": fields.String,
    "refresh_token": fields.String
}

retrieval_response_field = {
    "message": fields.String,
    "status": fields.String,
    "users": fields.List(fields.Nested(user_fields)),
    "bonuses": fields.List(fields.Nested(bonus_fields)),
}

# Admin-only decorator
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        admin = Admin.query.filter_by(admin_id=current_user_id).first()
        if not admin:
            return {"message": "Admins only!"}, 403
        return fn(*args, **kwargs)
    return wrapper

# Admin Resource
class AdminResource(Resource):
    """Admin Account Management"""

    parser = reqparse.RequestParser()
    parser.add_argument('name', type=str, required=False, help='Name is required')
    parser.add_argument('email', type=str, required=True, help='Email is required')
    parser.add_argument('password', type=str, required=True, help='Password is required')

    @marshal_with(auth_response_field)
    def post(self):
        """Admin Registration"""
        data = AdminResource.parser.parse_args()
        hashed_password = generate_password_hash(data['password']).decode('utf8')

        if Admin.query.filter_by(email=data['email']).first():
            return {"message": "Email already taken", "status": "fail"}, 400

        admin = Admin(name=data.get('name'), email=data['email'], password=hashed_password)
        db.session.add(admin)
        db.session.commit()

        access_token = create_access_token(identity=admin.admin_id)
        refresh_token = create_refresh_token(identity=admin.admin_id)

        return {
            "message": "Admin registered successfully!",
            "status": "success",
            "admins": [admin],
            "access_token": access_token,
            "refresh_token": refresh_token
        }, 201

    @marshal_with(auth_response_field)
    @jwt_required()
    def get(self, admin_id=None):
        """Get Admin Details"""
        current_admin_id = get_jwt_identity()
        admin = Admin.query.get(admin_id or current_admin_id)
        if not admin:
            return {"message": "Admin not found", "status": "fail"}, 404

        return {"message": "Admin retrieved successfully", "status": "success", "admins": [admin]}, 200

    @marshal_with(auth_response_field)
    @admin_required
    def put(self):
        """Update Admin Account"""
        data = AdminResource.parser.parse_args()
        admin_id = get_jwt_identity()
        admin = Admin.query.get(admin_id)

        if data.get('name'):
            admin.name = data['name']
        if data.get('email'):
            if Admin.query.filter_by(email=data['email']).first():
                return {"message": "Email already taken", "status": "fail"}, 400
            admin.email = data['email']
        if data.get('password'):
            admin.password = generate_password_hash(data['password']).decode('utf8')

        db.session.commit()
        return {"message": "Admin updated successfully", "status": "success", "admins": [admin]}, 200

    @marshal_with(auth_response_field)
    @admin_required
    def delete(self, admin_id):  # Handle admin_id as a parameter
        """Delete Admin Account"""
        admin = Admin.query.get(admin_id)  # Fetch admin by ID from URL
        if not admin:
            return {"message": "Admin not found", "status": "fail"}, 404

        db.session.delete(admin)
        db.session.commit()
        return {"message": "Admin account deleted successfully", "status": "success", "admins": []}, 200



# Admin Login Resource
class AdminLoginResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('email', type=str, required=True, help='Email is required')
    parser.add_argument('password', type=str, required=True, help='Password is required')

    @marshal_with(auth_response_field)
    def post(self):
        """Admin Login"""
        data = AdminLoginResource.parser.parse_args()

        admin = Admin.query.filter_by(email=data['email']).first()
        if not admin:
            return {"message": "Invalid email", "status": "fail"}, 401

        if not check_password_hash(admin.password, data['password']):
            return {"message": "Invalid password", "status": "fail"}, 401

        access_token = create_access_token(identity=admin.admin_id)
        refresh_token = create_refresh_token(identity=admin.admin_id)

        return {
            "message": "Login successful",
            "status": "success",
            "admins": [admin],
            "access_token": access_token,
            "refresh_token": refresh_token
        }, 200


class UserManagementResource(Resource):
    """Manage Users"""

    parser = reqparse.RequestParser()
    parser.add_argument('phone_number', type=str, required=True, help='Phone number is required')
    parser.add_argument('subscription', type=str, required=True, help='Subscription is required')
    parser.add_argument('expiry_time', type=str, required=True, help='Expiry time is required in the format YYYY-MM-DD')
    parser.add_argument('hotspot_id', type=int, required=True, help='Hotspot ID is required')

    @marshal_with(retrieval_response_field)
    @admin_required
    def post(self):
        """Create User"""
        data = UserManagementResource.parser.parse_args()

        # Parse expiry_time to datetime
        try:
            expiry_time = datetime.strptime(data['expiry_time'], '%Y-%m-%d')  # Ensure the format is YYYY-MM-DD
        except ValueError:
            return {"message": "Invalid expiry_time format. Use 'YYYY-MM-DD'.", "status": "fail"}, 400

        # Create the user object
        user = User(
            phone_number=data['phone_number'],
            subscription=data['subscription'],
            expiry_time=expiry_time,
            hotspot_id=data['hotspot_id']
        )

        try:
            db.session.add(user)
            db.session.commit()
            return {"message": "User added successfully!", "status": "success", "users": [user]}, 201
        except IntegrityError:
            db.session.rollback()
            return {"message": "User creation failed. Check for duplicate data.", "status": "fail"}, 409
    @marshal_with(retrieval_response_field)
    @admin_required
    def get(self, user_id=None):
        """Retrieve User(s)"""
        if user_id:
            user = User.query.get(user_id)
            if not user:
                return {"message": "User not found", "status": "fail"}, 404
            return {"message": "User retrieved successfully", "status": "success", "users": [user]}, 200
        users = User.query.all()
        return {"message": "Users retrieved successfully", "status": "success", "users": users}, 200

    @marshal_with(retrieval_response_field)
    @admin_required
    def put(self, user_id):
        """Update User Details"""
        data = UserManagementResource.parser.parse_args()

        # Find the user by ID
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found", "status": "fail"}, 404

        # Update fields conditionally
        user.phone_number = data['phone_number'] if data['phone_number'] else user.phone_number
        user.subscription = data['subscription'] if data['subscription'] else user.subscription

        # Handle expiry_time separately (parse it to datetime)
        if data['expiry_time']:
            try:
                user.expiry_time = datetime.strptime(data['expiry_time'], '%Y-%m-%d')
            except ValueError:
                return {"message": "Invalid expiry_time format. Use 'YYYY-MM-DD'.", "status": "fail"}, 400

        user.hotspot_id = data['hotspot_id'] if data['hotspot_id'] else user.hotspot_id

        # Save changes to the database
        try:
            db.session.commit()
            return {"message": "User updated successfully", "status": "success", "users": [user]}, 200
        except Exception as e:
            db.session.rollback()
            return {"message": f"Failed to update user: {str(e)}", "status": "fail"}, 500

    @marshal_with(retrieval_response_field)
    @admin_required
    def delete(self, user_id):
        """Delete User"""
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found", "status": "fail"}, 404

        db.session.delete(user)
        db.session.commit()
        return {"message": "User deleted successfully", "status": "success", "users": []}, 200
    
class HotspotManagementResource(Resource):
    """Manage Hotspots"""

    parser = reqparse.RequestParser()
    parser.add_argument('hotspot_name', type=str, required=True, help='Hotspot name is required')
    parser.add_argument('router_mac', type=str, required=True, help='Router MAC address is required')
    parser.add_argument('admin_id', type=int, required=True, help='Admin ID is required')

    @marshal_with(hotspot_response_field)
    @admin_required
    def post(self):
        """Add Hotspot"""
        data = HotspotManagementResource.parser.parse_args()
        hotspot = Hotspot(
            hotspot_name=data['hotspot_name'],
            router_mac=data['router_mac'],
            admin_id=data['admin_id']
        )
        try:
            db.session.add(hotspot)
            db.session.commit()
            return {"message": "Hotspot added successfully!", "status": "success", "hotspots": [hotspot]}, 201
        except IntegrityError:
            db.session.rollback()
            return {"message": "Hotspot creation failed. Check for duplicate data.", "status": "fail"}, 409

    @marshal_with(hotspot_response_field)
    @admin_required
    def get(self, hotspot_id=None):
        """Retrieve Hotspot(s)"""
        if hotspot_id:
            hotspot = Hotspot.query.get(hotspot_id)
            if not hotspot:
                return {"message": "Hotspot not found", "status": "fail"}, 404
            return {"message": "Hotspot retrieved successfully", "status": "success", "hotspots": [hotspot]}, 200
        hotspots = Hotspot.query.all()
        return {"message": "Hotspots retrieved successfully", "status": "success", "hotspots": hotspots}, 200

    @marshal_with(hotspot_response_field)
    @admin_required
    def put(self, hotspot_id):
        """Update Hotspot"""
        data = HotspotManagementResource.parser.parse_args()
        hotspot = Hotspot.query.get(hotspot_id)
        if not hotspot:
            return {"message": "Hotspot not found", "status": "fail"}, 404

        # Update fields conditionally
        hotspot.hotspot_name = data['hotspot_name'] if data['hotspot_name'] else hotspot.hotspot_name
        hotspot.router_mac = data['router_mac'] if data['router_mac'] else hotspot.router_mac
        hotspot.admin_id = data['admin_id'] if data['admin_id'] else hotspot.admin_id

        db.session.commit()
        return {"message": "Hotspot updated successfully", "status": "success", "hotspots": [hotspot]}, 200

    @marshal_with(hotspot_response_field)
    @admin_required
    def delete(self, hotspot_id):
        """Delete Hotspot"""
        hotspot = Hotspot.query.get(hotspot_id)
        if not hotspot:
            return {"message": "Hotspot not found", "status": "fail"}, 404

        db.session.delete(hotspot)
        db.session.commit()
        return {"message": "Hotspot deleted successfully", "status": "success", "hotspots": []}, 200

class PaymentManagementResource(Resource):
    """Manage Payments"""

    parser = reqparse.RequestParser()
    parser.add_argument('user_id', type=int, required=True, help="User ID is required")
    parser.add_argument('amount', type=float, required=True, help="Payment amount is required")
    parser.add_argument('hotspot_id', type=int, required=True, help="Hotspot ID is required")

    @marshal_with(payment_response_field)
    @admin_required
    def post(self):
        """Add Payment"""
        data = PaymentManagementResource.parser.parse_args()

        try:
            # Create and save the payment
            payment = Payment(
                user_id=data['user_id'],
                amount=data['amount'],
                hotspot_id=data['hotspot_id'],
                timestamp=datetime.utcnow()
            )
            db.session.add(payment)
            db.session.commit()
            return {"message": "Payment added successfully", "status": "success", "payments": [payment]}, 201
        except IntegrityError:
            db.session.rollback()
            return {"message": "Failed to add payment. Check user ID and hotspot ID.", "status": "fail"}, 400

    @marshal_with(payment_response_field)
    @admin_required
    def get(self, payment_id=None):
        """Retrieve Payment(s)"""
        if payment_id:
            payment = Payment.query.get(payment_id)
            if not payment:
                return {"message": "Payment not found", "status": "fail"}, 404
            return {"message": "Payment retrieved successfully", "status": "success", "payments": [payment]}, 200
        payments = Payment.query.all()
        return {"message": "Payments retrieved successfully", "status": "success", "payments": payments}, 200

    @marshal_with(payment_response_field)
    @admin_required
    def put(self, payment_id):
        """Update Payment"""
        data = PaymentManagementResource.parser.parse_args()

        # Retrieve the payment record
        payment = Payment.query.get(payment_id)
        if not payment:
            return {"message": "Payment not found", "status": "fail"}, 404

        # Update fields conditionally
        payment.user_id = data['user_id'] if data.get('user_id') else payment.user_id
        payment.amount = data['amount'] if data.get('amount') else payment.amount
        payment.hotspot_id = data['hotspot_id'] if data.get('hotspot_id') else payment.hotspot_id
        payment.timestamp = datetime.utcnow()  # Update the timestamp to the current time

        try:
            db.session.commit()
            return {"message": "Payment updated successfully", "status": "success", "payments": [payment]}, 200
        except IntegrityError:
            db.session.rollback()
            return {"message": "Failed to update payment. Check user ID and hotspot ID.", "status": "fail"}, 400

    @marshal_with(payment_response_field)
    @admin_required
    def delete(self, payment_id):
        """Delete Payment"""
        payment = Payment.query.get(payment_id)
        if not payment:
            return {"message": "Payment not found", "status": "fail"}, 404

        db.session.delete(payment)
        db.session.commit()
        return {"message": "Payment deleted successfully", "status": "success", "payments": []}, 200


class BonusManagementResource(Resource):
    """Manage Bonuses"""

    parser = reqparse.RequestParser()
    parser.add_argument('user_id', type=int, required=True, help='User ID is required')
    parser.add_argument('duration', type=int, required=True, help='Bonus duration is required')

    @marshal_with(retrieval_response_field)
    @admin_required
    def post(self):
        """Add Bonus"""
        data = BonusManagementResource.parser.parse_args()
        bonus = Bonus(
            admin_id=get_jwt_identity(),
            user_id=data['user_id'],
            duration=data['duration']
        )
        db.session.add(bonus)
        db.session.commit()
        return {"message": "Bonus added successfully!", "status": "success", "bonuses": [bonus]}, 201

    @marshal_with(retrieval_response_field)
    @admin_required
    def get(self, user_id=None):
        """Retrieve Bonuses"""
        bonuses = Bonus.query.filter_by(user_id=user_id).all() if user_id else Bonus.query.all()
        return {"message": "Bonuses retrieved successfully", "status": "success", "bonuses": bonuses}, 200


# Register Resources
admin_api = Api(admin_blueprint)
admin_api.add_resource(AdminResource, '/', '/<int:admin_id>')
admin_api.add_resource(AdminLoginResource, '/login')
admin_api.add_resource(UserManagementResource, '/user', '/user/<int:user_id>')
admin_api.add_resource(HotspotManagementResource, '/hotspot', '/hotspot/<int:hotspot_id>')
admin_api.add_resource(PaymentManagementResource, '/payment', '/payment/<int:payment_id>')
admin_api.add_resource(BonusManagementResource, '/bonus', '/user/<int:user_id>')
