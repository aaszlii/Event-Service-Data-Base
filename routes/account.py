from flask import Blueprint, jsonify, request
from extensions import db, bcrypt
from models import User, Client, Provider
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

account_blueprint = Blueprint('account', __name__)

@account_blueprint.route('/register', methods=['POST'])
def register():
    """
    Register a new user and validate fields before adding the user to the database.
    """
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        company_name = data.get('company_name')
        location = data.get('location')

        # General validation
        if not email or not password or not role:
            return jsonify({"message": "Missing required fields: email, password, or role"}), 400

        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"message": "Email already exists"}), 400

        # Role-specific validation before creating user
        if role == 'provider':
            if not company_name or not location:
                return jsonify({"message": "Missing provider-specific fields: company_name or location"}), 400
        elif role == 'client':
            if not first_name or not last_name:
                return jsonify({"message": "Missing client-specific fields: first_name or last_name"}), 400
        else:
            return jsonify({"message": "Invalid role"}), 400

        # Encrypt the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create the user
        new_user = User(email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        user_id = new_user.user_id

        # Add role-specific data
        if role == 'provider':
            new_provider = Provider(
                user_id=user_id,
                company_name=company_name,
                location=','.join(location)
            )
            db.session.add(new_provider)
        elif role == 'client':
            new_client = Client(
                user_id=user_id,
                first_name=first_name,
                last_name=last_name
            )
            db.session.add(new_client)

        db.session.commit()
        return jsonify({"message": "User registered successfully!"}), 201

    except Exception as e:
        print(f"Error during registration: {e}")
        db.session.rollback()

        # Handle specific SQLAlchemy integrity errors
        if "IntegrityError" in str(type(e)):
            return jsonify({"message": "A database integrity error occurred. Check for duplicate entries or missing data."}), 400

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

        # Pobierz użytkownika z bazy danych
        user = User.query.filter_by(email=email).first()
        if not user or not bcrypt.check_password_hash(user.password, password):
            return jsonify({"message": "Invalid credentials"}), 401

        # Generowanie tokenu JWT
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
