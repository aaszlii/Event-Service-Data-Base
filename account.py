from flask import Blueprint, jsonify, request
from extensions import db, bcrypt
from models import User, Client, Provider
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

account_blueprint = Blueprint('account', __name__)

@account_blueprint.route('/register', methods=['POST'])
def register():
    """
    Register a new user and, if role is provider, add them as a provider.
    """
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        company_name = data.get('company_name')
        location = data.get('location')

        # Data validation
        if not email or not password or not role:
            return jsonify({"message": "Missing required fields"}), 400

        # Password encryption
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create user
        new_user = User(email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        # Get the user_id of the new user
        user_id = new_user.user_id

        # If the user is a provider, add them to the providers table
        if role == 'provider':
            if not company_name or not location:
                return jsonify({"message": "Missing provider-specific fields"}), 400

            new_provider = Provider(
                user_id=user_id,
                company_name=company_name,
                location=','.join(location)
            )
            db.session.add(new_provider)

        db.session.commit()
        return jsonify({"message": "User registered successfully!"}), 201

    except Exception as e:
        print(f"Error during registration: {e}")
        db.session.rollback()
        return jsonify({"message": f"Error: {str(e)}"}), 500

@account_blueprint.route('/login', methods=['POST'])
def login():
    """
    Log in a user.
    """
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"message": "Missing required fields"}), 400

        # Retrieve the user from the database
        user = User.query.filter_by(email=email).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return jsonify({"message": "Invalid credentials"}), 401

        # Generate a JWT token
        access_token = create_access_token(identity={
            "id": user.user_id,
            "role": user.role,
            "email": user.email
        })

        return jsonify({"access_token": access_token}), 200

    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({"message": "Internal server error"}), 500


@account_blueprint.route('/delete', methods=['DELETE'])
@jwt_required()
def delete_account():
    """
    Allow a user to delete their account.
    """
    try:
        current_user = get_jwt_identity()
        user = User.query.filter_by(user_id=current_user['id']).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Cascade delete user-specific data
        db.session.delete(user)
        db.session.commit()

        return jsonify({"message": "Account deleted successfully!"}), 200

    except Exception as e:
        print(f"Error during account deletion: {e}")
        return jsonify({"message": "Internal server error"}), 500

@account_blueprint.route('/update', methods=['PUT'])
@jwt_required()
def update_account():
    """
    Allow a user to update their account details.
    """
    try:
        current_user = get_jwt_identity()
        data = request.json
        user = User.query.filter_by(user_id=current_user['id']).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        # Update user details
        email = data.get('email')
        password = data.get('password')

        if email:
            if User.query.filter_by(email=email).first():
                return jsonify({"message": "Email already exists"}), 400
            user.email = email

        if password:
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')

        db.session.commit()

        return jsonify({"message": "Account updated successfully!"}), 200

    except Exception as e:
        print(f"Error during account update: {e}")
        return jsonify({"message": "Internal server error"}), 500
