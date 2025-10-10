from flask import Flask
import os
from config import Config
from routes.auth_routes import auth_bp
from routes.admin_routes import admin_bp
from routes.file_routes import file_bp
from file_manager import FileManager

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(file_bp)

if __name__ == '__main__':
    FileManager.ensure_directories()
    app.run(debug=True)