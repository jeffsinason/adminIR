import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    IBM_CLIENT_ID = os.getenv("IBM_CLIENT_ID")
    IBM_CLIENT_SECRET = os.getenv("IBM_CLIENT_SECRET")
    IBM_INSTANCE_ID = os.getenv("IBM_INSTANCE_ID")
    API_KEY = os.getenv("API_KEY")
    HTTP_SERVER = 'https://api.p-vir-c1.appconnect.automation.ibm.com'
    REQUEST_VERSION = '/api/v1'
    LOG_FILE = "app.log"