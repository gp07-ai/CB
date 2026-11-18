# Agent configuration
import os

CENTRAL_SERVER_URL = os.environ.get('CENTRAL_SERVER_URL', 'http://localhost:5000')
AGENT_ID = os.environ.get('AGENT_ID', '1')
AGENT_TOKEN = os.environ.get('AGENT_TOKEN', 'token-alpha')
AGENT_NAME = os.environ.get('AGENT_NAME', 'Agent-Alpha')
HEARTBEAT_INTERVAL = int(os.environ.get('HEARTBEAT_INTERVAL', '30'))  # seconds
EVENT_SEND_INTERVAL = int(os.environ.get('EVENT_SEND_INTERVAL', '5'))  # seconds
