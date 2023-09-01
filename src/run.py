from app import app
import os
from waitress import serve

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=6969)