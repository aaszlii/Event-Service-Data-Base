from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import Availability, db, Provider

availability_blueprint = Blueprint('availability', __name__)

@availability_blueprint.route('', methods=['POST'])
@jwt_required()
def add_availability():
    current_user = get_jwt_identity()

    if current_user['role'] != 'provider':
        return jsonify({"message": "Access forbidden"}), 403

    provider = db.session.query(Provider).filter_by(user_id=current_user['id']).first()
    if not provider:
        return jsonify({"message": "No provider found for the current user"}), 404

    data = request.json
    service_id = data.get('service_id')
    available_date = data.get('available_date')
    daily_limit = data.get('daily_limit', 1)

    if not service_id or not available_date:
        return jsonify({"message": "Missing required fields"}), 400

    new_availability = Availability(
        service_id=service_id,
        provider_id=provider.provider_id,
        available_date=available_date,
        daily_limit=daily_limit
    )

    db.session.add(new_availability)
    db.session.commit()

    return jsonify({"message": "Availability added successfully!"}), 201

@availability_blueprint.route('/<int:availability_id>', methods=['PUT'])
@jwt_required()
def edit_availability(availability_id):
    current_user = get_jwt_identity()

    provider = db.session.query(Provider).filter_by(user_id=current_user['id']).first()
    if not provider:
        return jsonify({"message": "No provider found for the current user"}), 404

    availability = Availability.query.get(availability_id)
    if not availability or availability.provider_id != provider.provider_id:
        return jsonify({"message": "Access forbidden or availability not found"}), 404

    data = request.json
    daily_limit = data.get('daily_limit')

    if daily_limit is not None:
        availability.daily_limit = daily_limit

    db.session.commit()
    return jsonify({"message": "Availability updated successfully!"}), 200

@availability_blueprint.route('/<int:availability_id>', methods=['DELETE'])
@jwt_required()
def delete_availability(availability_id):
    current_user = get_jwt_identity()

    provider = db.session.query(Provider).filter_by(user_id=current_user['id']).first()
    if not provider:
        return jsonify({"message": "No provider found for the current user"}), 404

    availability = Availability.query.get(availability_id)
    if not availability or availability.provider_id != provider.provider_id:
        return jsonify({"message": "Access forbidden or availability not found"}), 404

    db.session.delete(availability)
    db.session.commit()
    return jsonify({"message": "Availability deleted successfully!"}), 200

@availability_blueprint.route('', methods=['GET'])
@jwt_required()
def get_available_dates():
    current_user = get_jwt_identity()
    print(f"User: {current_user}")

    # Pobierz parametry zapytania
    service_id = request.args.get('service_id')
    provider_id = request.args.get('provider_id')
    print(f"Service ID: {service_id}, Provider ID: {provider_id}")

    # Budowanie zapytania
    query = Availability.query

    if current_user['role'] == 'client':
        query = query.filter_by(status='available')

    if service_id:
        query = query.filter_by(service_id=service_id)
    if provider_id:
        query = query.filter_by(provider_id=provider_id)

    available_dates = query.all()

    print(f"Available dates: {available_dates}")

    return jsonify([
        {
            "availability_id": date.availability_id,
            "service_id": date.service_id,
            "provider_id": date.provider_id,
            "available_date": date.available_date.isoformat(),
            "daily_limit": date.daily_limit,
            "status": date.status
        }
        for date in available_dates
    ]), 200
