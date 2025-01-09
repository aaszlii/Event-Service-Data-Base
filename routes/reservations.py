from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import Reservation, Availability, db, Client, Provider, Review

reservations_blueprint = Blueprint('reservations', __name__)

@reservations_blueprint.route('', methods=['POST'])
@jwt_required()
def make_reservation():
    current_user = get_jwt_identity()
    if not request.headers.get("Authorization"):
        return jsonify({"message": "Missing Authorization Header"}), 401

    if current_user['role'] != 'client':
        return jsonify({"message": "Access forbidden"}), 403

    data = request.json
    service_id = data['service_id']
    provider_id = data['provider_id']
    reservation_date = data['reservation_date']

    # Fetch client_id using user_id
    client = Client.query.filter_by(user_id=current_user['id']).first()
    if not client:
        return jsonify({"message": "Client not found"}), 404

    print(f"Service ID: {service_id}, Provider ID: {provider_id}, Reservation Date: {reservation_date}")
    availability = Availability.query.filter_by(
        service_id=service_id,
        provider_id=provider_id,
        available_date=reservation_date,
        status='available'
    ).first()
    print(f"Availability found: {availability}")

    if not availability or availability.daily_limit <= 0:
        return jsonify({"message": "No availability"}), 400

    # Tworzenie rezerwacji
    reservation = Reservation(
        service_id=service_id,
        provider_id=provider_id,
        client_id=client.client_id,
        reservation_date=reservation_date,
        status='pending'
    )
    db.session.add(reservation)

    # Zmniejsz limit dzienny
    availability.daily_limit -= 1

    # Oznacz datę jako zajętą, jeśli daily_limit wynosi 0
    if availability.daily_limit == 0:
        availability.status = 'booked'

    db.session.commit()
    return jsonify({"message": "Reservation successful!"}), 201

@reservations_blueprint.route('/<int:reservation_id>', methods=['DELETE'])
@jwt_required()
def cancel_reservation(reservation_id):
    current_user = get_jwt_identity()
    reservation = Reservation.query.filter_by(reservation_id=reservation_id).first()

    if not reservation:
        return jsonify({"message": "Reservation not found"}), 404

    if current_user['role'] == 'client':
        client = Client.query.filter_by(user_id=current_user['id']).first()
        if not client or reservation.client_id != client.client_id:
            return jsonify({"message": "Access forbidden"}), 403
    elif current_user['role'] == 'provider':
        provider = Provider.query.filter_by(user_id=current_user['id']).first()
        if not provider or reservation.provider_id != provider.provider_id:
            return jsonify({"message": "Access forbidden"}), 403

    print(f"Before update: {reservation.status if reservation.status else 'None'}")
    reservation.status = 'cancelled'
    print(f"After update: {reservation.status if reservation.status else 'None'}")

    availability = Availability.query.filter_by(
        service_id=reservation.service_id,
        provider_id=reservation.provider_id,
        available_date=reservation.reservation_date
    ).first()

    if availability:
        availability.daily_limit += 1
        if availability.daily_limit > 0:
            availability.status = 'available'

    db.session.commit()
    return jsonify({"message": "Reservation cancelled successfully!"}), 200

@reservations_blueprint.route('/history', methods=['GET'])
@jwt_required()
def get_reservation_history():
    current_user = get_jwt_identity()
    query = Reservation.query

    if current_user['role'] == 'client':
        client = Client.query.filter_by(user_id=current_user['id']).first()
        if not client:
            return jsonify({"message": "Client not found"}), 404
        query = query.filter_by(client_id=client.client_id)
    elif current_user['role'] == 'provider':
        provider = Provider.query.filter_by(user_id=current_user['id']).first()
        if not provider:
            return jsonify({"message": "Provider not found"}), 404
        query = query.filter_by(provider_id=provider.provider_id)
    else:
        return jsonify({"message": "Access forbidden"}), 403

    reservations = query.all()
    return jsonify([
        {
            "reservation_id": res.reservation_id,
            "provider_id": res.provider_id,
            "service_id": res.service_id,
            "reservation_date": res.reservation_date.isoformat(),
            "status": res.status
        }
        for res in reservations
    ]), 200

@reservations_blueprint.route('/<int:reservation_id>', methods=['GET'])
@jwt_required()
def get_reservation_status(reservation_id):
    current_user = get_jwt_identity()
    reservation = Reservation.query.filter_by(reservation_id=reservation_id).first()

    if not reservation:
        return jsonify({"message": "Reservation not found"}), 404

    if current_user['role'] == 'client':
        client = Client.query.filter_by(user_id=current_user['id']).first()
        if not client or reservation.client_id != client.client_id:
            return jsonify({"message": "Access forbidden"}), 403
    elif current_user['role'] == 'provider':
        provider = Provider.query.filter_by(user_id=current_user['id']).first()
        if not provider or reservation.provider_id != provider.provider_id:
            return jsonify({"message": "Access forbidden"}), 403

    return jsonify({
        "reservation_id": reservation.reservation_id,
        "provider_id": reservation.provider_id,
        "service_id": reservation.service_id,
        "reservation_date": reservation.reservation_date.isoformat(),
        "status": reservation.status
    }), 200

@reservations_blueprint.route('/<int:reservation_id>/status', methods=['PUT'])
@jwt_required()
def update_reservation_status(reservation_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'provider':
        return jsonify({"message": "Access forbidden"}), 403

    provider = Provider.query.filter_by(user_id=current_user['id']).first()
    if not provider:
        return jsonify({"message": "Provider not found"}), 404

    data = request.json
    new_status = data.get('status')

    if new_status not in ['confirmed', 'completed', 'cancelled']:
        return jsonify({"message": "Invalid status"}), 400

    reservation = Reservation.query.filter_by(
        reservation_id=reservation_id,
        provider_id=provider.provider_id
    ).first()

    if not reservation:
        return jsonify({"message": "Reservation not found"}), 404

    reservation.status = new_status
    db.session.commit()
    return jsonify({"message": "Reservation status updated successfully!"}), 200

@reservations_blueprint.route('/<int:reservation_id>/review', methods=['POST'])
@jwt_required()
def add_review(reservation_id):
    """
    Dodaj opinię dla zakończonej rezerwacji.
    Każdy użytkownik może dodać tylko jedną opinię do jednej rezerwacji.
    """
    current_user = get_jwt_identity()

    if current_user['role'] != 'client':
        return jsonify({"message": "Access forbidden"}), 403

    data = request.json
    rating = data.get('rating')
    comment = data.get('comment')

    if not rating:
        return jsonify({"message": "Rating is required"}), 400

    # Znajdź rezerwację
    reservation = Reservation.query.filter_by(reservation_id=reservation_id).first()
    if not reservation or reservation.status != 'completed':
        return jsonify({"message": "Reservation not found or not completed"}), 404

    # Znajdź klienta
    client = Client.query.filter_by(user_id=current_user['id']).first()
    if not client or reservation.client_id != client.client_id:
        return jsonify({"message": "Access forbidden"}), 403

    # Sprawdź, czy opinia już istnieje
    existing_review = Review.query.filter_by(reservation_id=reservation_id, client_id=client.client_id).first()
    if existing_review:
        return jsonify({"message": "You have already reviewed this reservation"}), 400

    # Tworzenie nowej opinii
    review = Review(
        reservation_id=reservation_id,
        service_id=reservation.service_id,
        client_id=client.client_id,
        rating=rating,
        comment=comment
    )
    db.session.add(review)
    db.session.commit()

    return jsonify({"message": "Review added successfully!"}), 201
