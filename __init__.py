def register_blueprints(app):
    from .reservations import reservations_blueprint
    from .services import services_blueprint
    from .account import account_blueprint
    from .availability import availability_blueprint

    app.register_blueprint(reservations_blueprint, url_prefix="/reservations")
    app.register_blueprint(services_blueprint, url_prefix="/services")
    app.register_blueprint(availability_blueprint, url_prefix="/availability")
    app.register_blueprint(account_blueprint, url_prefix="/account")
