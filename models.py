from extensions import db
from sqlalchemy.dialects.mysql import ENUM

class User(db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Administrator(db.Model):
    __tablename__ = 'administrators'

    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete="CASCADE"), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    permissions = db.Column(db.Enum('full', 'restricted', 'read-only'), default='restricted', nullable=False)

    user = db.relationship('User', backref='administrator', lazy=True)

class Provider(db.Model):
    __tablename__ = 'providers'

    provider_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(255), nullable=False)

    # Relacja z tabelą `users`
    user = db.relationship('User', backref='provider', lazy=True)

    # Relacja z tabelą `services`
    services = db.relationship('Service', backref='provider', lazy=True)

    # Relacja z tabelą `specializations`
    specializations = db.relationship(
        'Specialization',
        secondary='provider_specializations',
        back_populates='providers',
        lazy='dynamic'
    )

class ProviderSpecialization(db.Model):
    __tablename__ = 'provider_specializations'
    provider_id = db.Column(db.Integer, db.ForeignKey('providers.provider_id', ondelete="CASCADE"), primary_key=True)
    specialization_id = db.Column(db.Integer, db.ForeignKey('specializations.specialization_id', ondelete="CASCADE"), primary_key=True)

class Specialization(db.Model):
    __tablename__ = 'specializations'
    specialization_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True)

    providers = db.relationship(
        'Provider',
        secondary='provider_specializations',
        back_populates='specializations'
    )

class Service(db.Model):
    __tablename__ = 'services'

    service_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('providers.provider_id', ondelete="CASCADE"), nullable=False)
    specialization_id = db.Column(db.Integer, db.ForeignKey('specializations.specialization_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    price = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Reservation(db.Model):
    __tablename__ = 'reservations'

    reservation_id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.client_id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('providers.provider_id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.service_id'), nullable=False)
    reservation_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Enum('pending', 'confirmed', 'completed', 'cancelled'), default='pending', nullable=False)

class Review(db.Model):
    __tablename__ = 'reviews'

    review_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    service_id = db.Column(db.Integer, db.ForeignKey('services.service_id'), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.client_id'), nullable=False)
    rating = db.Column(db.Float, nullable=False)
    comment = db.Column(db.Text, nullable=True)  # Komentarz jest opcjonalny
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp(), nullable=False)
    reservation_id = db.Column(db.Integer, db.ForeignKey('reservations.reservation_id'), nullable=False)

    # Relacje dla ORM
    service = db.relationship('Service', backref='reviews', lazy=True)
    client = db.relationship('Client', backref='reviews', lazy=True)
    reservation = db.relationship('Reservation', backref='reviews', lazy=True)

    def __repr__(self):
        return f"<Review(review_id={self.review_id}, service_id={self.service_id}, client_id={self.client_id}, rating={self.rating}, comment={self.comment})>"

class Availability(db.Model):
    __tablename__ = 'available_dates'  # Poprawna nazwa tabeli
    availability_id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, nullable=False)
    provider_id = db.Column(db.Integer, nullable=False)
    available_date = db.Column(db.Date, nullable=False)
    daily_limit = db.Column(db.Integer, default=0)
    status = db.Column(db.String(50), nullable=False, default='available')

class Client(db.Model):
    __tablename__ = 'clients'
    client_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete="CASCADE"), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
