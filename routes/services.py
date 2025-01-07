from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Provider, Service, Specialization, ProviderSpecialization, Client, Review

services_blueprint = Blueprint('services', __name__)

@services_blueprint.route('/providers', methods=['GET'])
def search_providers():
    """
    Search providers with optional filters for specialization and location.
    """
    specialization = request.args.get('specialization')
    location = request.args.get('location')

    query = Provider.query

    # Filter by specialization if provided
    if specialization:
        query = query.join(ProviderSpecialization).join(Specialization).filter(Specialization.name == specialization)

    # Filter by location if provided
    if location:
        query = query.filter(Provider.location.like(f"%{location}%"))

    providers = query.all()

    result = [
        {
            "id": provider.provider_id,
            "company_name": provider.company_name,
            "location": provider.location,
            "specializations": [
                spec.name for spec in Specialization.query.join(ProviderSpecialization)
                .filter(ProviderSpecialization.provider_id == provider.provider_id).all()
            ]
        } for provider in providers
    ]

    return jsonify(result), 200

@services_blueprint.route('/providers/<int:provider_id>', methods=['GET'])
def get_provider_details(provider_id):
    """
    Retrieve detailed information about a specific provider, including their services.
    """
    try:
        provider = Provider.query.filter_by(provider_id=provider_id).first()

        if not provider:
            return jsonify({"message": "Provider not found"}), 404

        services = Service.query.filter_by(provider_id=provider_id).all()

        return jsonify({
            "provider_id": provider.provider_id,
            "company_name": provider.company_name,
            "location": provider.location,
            "specializations": [
                specialization.name for specialization in provider.specializations
            ],
            "services": [
                {
                    "service_id": service.service_id,
                    "name": service.name,
                    "description": service.description,
                    "price": float(service.price),
                    "specialization": Specialization.query.filter_by(specialization_id=service.specialization_id).first().name
                } for service in services
            ]
        }), 200
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

@services_blueprint.route('/assign-specializations', methods=['POST'])
@jwt_required()
def assign_specializations():
    """
    Assign specializations to the currently logged-in provider.
    """
    try:
        current_user = get_jwt_identity()
        provider = Provider.query.filter_by(user_id=current_user['id']).first()

        if not provider:
            return jsonify({"message": "Provider not found"}), 404

        data = request.json
        specializations = data.get('specializations')

        if not specializations:
            return jsonify({"message": "No specializations provided"}), 400

        for specialization_id in specializations:
            existing_entry = ProviderSpecialization.query.filter_by(
                provider_id=provider.provider_id, specialization_id=specialization_id
            ).first()

            if not existing_entry:
                new_entry = ProviderSpecialization(
                    provider_id=provider.provider_id, specialization_id=specialization_id
                )
                db.session.add(new_entry)

        db.session.commit()
        return jsonify({"message": "Specializations assigned successfully"}), 201

    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

@services_blueprint.route('/add-service', methods=['POST'])
@jwt_required()
def add_service():
    """
    Add a service for the currently logged-in provider.
    """
    try:
        current_user = get_jwt_identity()
        provider = Provider.query.filter_by(user_id=current_user['id']).first()

        if not provider:
            return jsonify({"message": "Provider not found"}), 404

        data = request.json
        name = data.get('service_name')
        description = data.get('description')
        price = data.get('price')
        specialization_id = data.get('specialization_id')

        if not name or not price or not specialization_id:
            return jsonify({"message": "Missing required fields"}), 400

        new_service = Service(
            provider_id=provider.provider_id,
            specialization_id=specialization_id,
            name=name,
            description=description,
            price=price
        )
        db.session.add(new_service)
        db.session.commit()

        return jsonify({"message": "Service added successfully"}), 201

    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

@services_blueprint.route('/<int:service_id>', methods=['PUT'])
@jwt_required()
def edit_service(service_id):
    try:
        # Fetch the logged-in user
        current_user = get_jwt_identity()

        # Validate if the logged-in user is a provider
        provider = Provider.query.filter_by(user_id=current_user['id']).first()
        if not provider:
            return jsonify({"message": "Access forbidden"}), 403

        # Find the service and validate ownership
        service = Service.query.filter_by(service_id=service_id, provider_id=provider.provider_id).first()
        if not service:
            return jsonify({"message": "Service not found"}), 404

        # Update service details
        data = request.json
        if 'name' in data:
            service.name = data['name']
        if 'description' in data:
            service.description = data['description']
        if 'price' in data:
            service.price = data['price']

        db.session.commit()
        return jsonify({"message": "Service updated successfully!"}), 200

    except Exception as e:
        print(f"Error during service update: {e}")
        return jsonify({"message": "Internal server error"}), 500

@services_blueprint.route('/<int:service_id>', methods=['DELETE'])
@jwt_required()
def delete_service(service_id):
    """
    Delete a service by the provider.
    """
    try:
        # Get the current logged-in user
        current_user = get_jwt_identity()

        # Validate if the logged-in user is a provider
        provider = Provider.query.filter_by(user_id=current_user['id']).first()
        if not provider:
            return jsonify({"message": "Access forbidden"}), 403

        # Find the service and ensure it belongs to the logged-in provider
        service = Service.query.filter_by(service_id=service_id, provider_id=provider.provider_id).first()
        if not service:
            return jsonify({"message": "Service not found"}), 404

        # Delete the service
        db.session.delete(service)
        db.session.commit()
        return jsonify({"message": "Service deleted successfully!"}), 200

    except Exception as e:
        print(f"Error during service deletion: {e}")
        return jsonify({"message": "Internal server error"}), 500

@services_blueprint.route('/<int:service_id>/reviews', methods=['GET'])
@jwt_required()
def get_service_reviews(service_id):
    """
    Retrieve all reviews for a specific service, including average rating, total count, and reviewer details.
    """
    # Fetch reviews for the specified service
    reviews = Review.query.filter_by(service_id=service_id).all()

    if not reviews:
        return jsonify({
            "message": "No reviews found for the specified service.",
            "average_rating": None,
            "total_reviews": 0,
            "reviews": []
        }), 200

    # Calculate average rating
    total_rating = sum(review.rating for review in reviews)
    average_rating = total_rating / len(reviews)
    total_reviews = len(reviews)

    # Prepare review details
    review_details = []
    for review in reviews:
        client = Client.query.filter_by(client_id=review.client_id).first()
        review_details.append({
            "client_name": f"{client.first_name} {client.last_name}" if client else "Anonymous",
            "rating": review.rating,
            "comment": review.comment
        })

    # Return results
    return jsonify({
        "average_rating": round(average_rating, 2),
        "total_reviews": total_reviews,
        "reviews": review_details
    }), 200
