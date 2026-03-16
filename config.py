import os
from dotenv import load_dotenv

load_dotenv()

GCP_PROJECT = os.environ["GCP_PROJECT"]
GCP_LOCATION = os.getenv("GCP_LOCATION", "us-central1")
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.5-flash")
DB_PATH = os.getenv("DB_PATH", "demo_database.db")

# Model Armor — set template ID in .env to enable; leave empty to run in placeholder mode
MODEL_ARMOR_TEMPLATE_ID = os.getenv("MODEL_ARMOR_TEMPLATE_ID", "")

TENANTS = [
    {"id": 1, "name": "Nakatomi Trading"},
    {"id": 2, "name": "Cyberdyne Systems"},
    {"id": 3, "name": "Massive Dynamic"},
]
