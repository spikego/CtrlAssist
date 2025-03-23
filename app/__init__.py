from flask import Flask
import os

def clear_data():
    # Implement the logic to clear data
    if os.path.exists('data'):
        for file in os.listdir('data'):
            file_path = os.path.join('data', file)
            if os.path.isfile(file_path):
                os.unlink(file_path)

def create_app():
    app = Flask(__name__)
    from .routes import main
    app.register_blueprint(main)
    clear_data()  # Clear data on startup
    return app
