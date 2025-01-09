from flask import Flask
from config import Config
from extensions import db, jwt, bcrypt
from routes import register_blueprints

def create_app():
    """
    Application factory to create and configure the Flask application.
    """
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)

    # Register blueprints
    register_blueprints(app)

    return app

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            print(f"Error creating database tables: {e}")
    app.run(debug=True)
    print(app.url_map)


