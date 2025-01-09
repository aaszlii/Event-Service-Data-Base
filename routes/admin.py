from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import bcrypt
from models import User, Review, Provider, Client, db, Specialization, Administrator

admin_blueprint = Blueprint('admin', __name__)

@admin_blueprint.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = get_jwt_identity()
    if current_user['role'] != 'administrator':
        return jsonify({"message": "Access forbidden"}), 403

    users = User.query.all()
    result = [
        {
            "user_id": user.user_id,
            "email": user.email,
            "role": user.role
        } for user in users
    ]
    return jsonify(result), 200

@admin_blueprint.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'administrator':
        return jsonify({"message": "Access forbidden"}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully!"}), 200

@admin_blueprint.route('/reviews/<int:review_id>', methods=['DELETE'])
@jwt_required()
def delete_review(review_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'administrator':
        return jsonify({"message": "Access forbidden"}), 403

    review = Review.query.get(review_id)
    if not review:
        return jsonify({"message": "Review not found"}), 404

    db.session.delete(review)
    db.session.commit()
    return jsonify({"message": "Review deleted successfully!"}), 200

@admin_blueprint.route('/add-specialization', methods=['POST'])
@jwt_required()
def add_specialization():
    """
    Add a new specialization to the platform.
    """
    try:
        current_user = get_jwt_identity()
        if current_user['role'] != 'administrator':
            return jsonify({"message": "Access forbidden"}), 403

        data = request.json
        name = data.get('name')

        if not name:
            return jsonify({"message": "Specialization name is required"}), 400

        # Check if specialization already exists
        existing_specialization = Specialization.query.filter_by(name=name).first()
        if existing_specialization:
            return jsonify({"message": "Specialization already exists"}), 400

        # Add new specialization
        new_specialization = Specialization(name=name)
        db.session.add(new_specialization)
        db.session.commit()

        return jsonify({
            "message": "Specialization added successfully!",
            "specialization_id": new_specialization.specialization_id
        }), 201

    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

@admin_blueprint.route('/specializations/<int:specialization_id>', methods=['DELETE'])
@jwt_required()
def delete_specialization(specialization_id):
    """
    Delete a specialization.
    """
    current_user = get_jwt_identity()
    if current_user['role'] != 'administrator':
        return jsonify({"message": "Access forbidden"}), 403

    specialization = Specialization.query.get(specialization_id)
    if not specialization:
        return jsonify({"message": "Specialization not found"}), 404

    # Check if the specialization is linked to any providers
    if specialization.providers:  # Wystarczy sprawdzić, czy lista nie jest pusta
        return jsonify({"message": "Specialization cannot be deleted because it is linked to providers"}), 400

    db.session.delete(specialization)
    db.session.commit()
    return jsonify({"message": "Specialization deleted successfully!"}), 200

@admin_blueprint.route('/create-admin', methods=['POST'])
@jwt_required()
def create_admin():
    """
    Create a new administrator user and ensure they are added as a user and administrator.
    """
    current_user = get_jwt_identity()
    if current_user['role'] != 'administrator':
        return jsonify({"message": "Access forbidden"}), 403

    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        permissions = data.get('permissions', 'restricted')

        # General validation
        if not email or not password or not first_name or not last_name:
            return jsonify({"message": "Missing required fields"}), 400

        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"message": "Email already exists"}), 400

        # Encrypt the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create the user
        new_user = User(email=email, password=hashed_password, role='administrator')
        db.session.add(new_user)
        db.session.flush()  # Ensure new_user.user_id is available

        # Create the administrator
        new_admin = Administrator(
            user_id=new_user.user_id,
            first_name=first_name,
            last_name=last_name,
            permissions=permissions
        )
        db.session.add(new_admin)
        db.session.commit()

        return jsonify({"message": "Administrator created successfully!"}), 201

    except Exception as e:
        db.session.rollback()

        # Handle specific SQLAlchemy integrity errors
        if "IntegrityError" in str(type(e)):
            return jsonify({"message": "A database integrity error occurred. Check for duplicate entries or missing data."}), 400

        return jsonify({"message": f"Error: {str(e)}"}), 500

@admin_blueprint.route('/reports/activity', methods=['GET'])
@jwt_required()
def get_platform_activity():
    current_user = get_jwt_identity()
    if current_user['role'] != 'administrator':
        return jsonify({"message": "Access forbidden"}), 403

    total_users = User.query.count()
    total_providers = Provider.query.count()
    total_clients = Client.query.count()
    total_reviews = Review.query.count()

    return jsonify({
        "total_users": total_users,
        "total_providers": total_providers,
        "total_clients": total_clients,
        "total_reviews": total_reviews
    }), 200
