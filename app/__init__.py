from flask import Flask
from fastapi import FastAPI
from .config import Config
from .utils.logger import configure_logging

# Configure logging
logger = configure_logging()

# Create FastAPI app
fastapi_app = FastAPI()

# Create Flask app
flask_app = Flask(__name__)
flask_app.config.from_object(Config)

logger.info("Apps initialized successfully.")