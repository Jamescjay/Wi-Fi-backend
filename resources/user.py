from flask import Blueprint
from flask_restful import Resource, reqparse, fields, marshal_with, Api
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from models import db, User, Payment, Bonus

# User Blueprint
user_blueprint = Blueprint('user', __name__)

# Field definitions for user responses
payment_fields = {
    'payment_id': fields.Integer,
    'user_id': fields.Integer,
    'amount': fields.Float,
    'hotspot_id': fields.Integer,
    'timestamp': fields.String
}


bonus_fields = {
    'bonus_id': fields.Integer,
    'user_id': fields.Integer,
    'duration': fields.Integer
}

user_response_field = {
    "message": fields.String,
    "status": fields.String,
    "payments": fields.List(fields.Nested(payment_fields)),
    "bonuses": fields.List(fields.Nested(bonus_fields))
}

class UserLoginResource(Resource):
    """User Login"""

    parser = reqparse.RequestParser()
    parser.add_argument('phone_number', type=str, required=True, help="Phone number is required")
    parser.add_argument('password', type=str, required=True, help="Password is required")

    def post(self):
        """User Login"""
        data = UserLoginResource.parser.parse_args()
        user = User.query.filter_by(phone_number=data['phone_number']).first()

        if not user or user.phone_number != data['password']:  # using phone number as the password
            return {"message": "Invalid credentials", "status": "fail"}, 401

        access_token = create_access_token(identity=user.user_id)
        refresh_token = create_refresh_token(identity=user.user_id)
        return {
            "message": "Login successful",
            "status": "success",
            "access_token": access_token,
            "refresh_token": refresh_token
        }, 200

class UserPaymentResource(Resource):
    """Retrieve User Payments and Bonuses"""

    @marshal_with(user_response_field)
    @jwt_required()
    def get(self):
        """Get User Payments and Bonuses"""
        user_id = get_jwt_identity()

        payments = Payment.query.filter_by(user_id=user_id).all()
        bonuses = Bonus.query.filter_by(user_id=user_id).all()

        return {
            "message": "User payments and bonuses retrieved successfully",
            "status": "success",
            "payments": payments,
            "bonuses": bonuses
        }, 200


user_api = Api(user_blueprint)
user_api.add_resource(UserLoginResource, '/login')
user_api.add_resource(UserPaymentResource, '/payments')