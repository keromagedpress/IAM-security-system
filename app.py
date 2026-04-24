import os
from dotenv import load_dotenv
from flask import Flask
import secrets
from routes import bp
from cli import register_commands
from datetime import timedelta
import threading
from os_monitor import monitor_loop

# Load environment configuration
load_dotenv()

app = Flask(__name__)

# Security Configuration
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(64))
# Enforce 30-minute session timeout
app.permanent_session_lifetime = timedelta(minutes=30)

# Register routes from routes.py
app.register_blueprint(bp)

# Register CLI commands from cli.py
register_commands(app)

if __name__ == '__main__':
    # Start the OS Monitoring thread (heartbeat every 5 mins)
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    
    # Run the app
    debug_mode = os.getenv('FLASK_DEBUG', 'True') == 'True'
    port = int(os.getenv('FLASK_PORT', 5000))
    app.run(debug=debug_mode, port=port)
