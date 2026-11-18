import hashlib
from functools import wraps
from flask import Blueprint, request, session, redirect, url_for, jsonify
from database import get_db_connection
from detection.detection_engine import analyze_event

agents_bp = Blueprint('agents', __name__, url_prefix='/api/agents')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _verify_agent_token(agent_id: int, agent_token: str):
    """Return agent row if token matches, else None."""
    token_hash = _hash_token(agent_token)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'SELECT id, agent_name, status FROM agents WHERE id = %s AND agent_token_hash = %s',
        (agent_id, token_hash)
    )
    agent = cursor.fetchone()
    cursor.close()
    conn.close()
    return agent


@agents_bp.route('/', methods=['GET'])
@login_required
def list_agents():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, agent_name, ip_address, status, last_seen FROM agents ORDER BY id')
        agents = cursor.fetchall()
        cursor.close()
        conn.close()

        def serialize(row):
            return {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in row.items()}

        return jsonify({'status': 'ok', 'agents': [serialize(a) for a in agents]})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@agents_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or request.form
    agent_name = data.get('agent_name', '').strip()
    agent_token = data.get('agent_token', '').strip()

    if not agent_name or not agent_token:
        return jsonify({'status': 'error', 'message': 'agent_name and agent_token are required'}), 400

    token_hash = _hash_token(agent_token)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO agents (agent_name, agent_token_hash, status) VALUES (%s, %s, %s)',
            (agent_name, token_hash, 'offline')
        )
        agent_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'status': 'registered', 'agent_id': agent_id, 'agent_name': agent_name}), 201
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@agents_bp.route('/heartbeat', methods=['POST'])
def heartbeat():
    data = request.get_json(silent=True) or request.form
    agent_id = data.get('agent_id')
    agent_token = data.get('agent_token', '')

    if not agent_id or not agent_token:
        return jsonify({'status': 'error', 'message': 'agent_id and agent_token are required'}), 400

    try:
        agent_id = int(agent_id)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid agent_id'}), 400

    agent = _verify_agent_token(agent_id, agent_token)
    if not agent:
        return jsonify({'status': 'error', 'message': 'Invalid agent credentials'}), 401

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE agents SET status = 'online', last_seen = NOW() WHERE id = %s",
            (agent_id,)
        )
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'status': 'ok', 'agent_id': agent_id, 'agent_name': agent['agent_name']})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@agents_bp.route('/submit_event', methods=['POST'])
def submit_event():
    data = request.get_json(silent=True) or request.form

    agent_id = data.get('agent_id')
    agent_token = data.get('agent_token', '')
    source_ip = data.get('source_ip', '')
    destination_ip = data.get('destination_ip', '')
    protocol = data.get('protocol', '')
    destination_port = data.get('destination_port')
    event_type = data.get('event_type', '')

    if not agent_id or not agent_token:
        return jsonify({'status': 'error', 'message': 'agent_id and agent_token are required'}), 400

    try:
        agent_id = int(agent_id)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Invalid agent_id'}), 400

    agent = _verify_agent_token(agent_id, agent_token)
    if not agent:
        return jsonify({'status': 'error', 'message': 'Invalid agent credentials'}), 401

    try:
        destination_port = int(destination_port) if destination_port else None
    except (ValueError, TypeError):
        destination_port = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO network_events
               (agent_id, source_ip, destination_ip, protocol, destination_port, event_type)
               VALUES (%s, %s, %s, %s, %s, %s)''',
            (agent_id, source_ip, destination_ip, protocol, destination_port, event_type)
        )
        event_id = cursor.lastrowid
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

    # Run detection analysis
    alerts_generated = []
    try:
        event_data = {
            'event_id': event_id,
            'agent_id': agent_id,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'protocol': protocol,
            'destination_port': destination_port,
            'event_type': event_type,
        }
        result = analyze_event(event_data)
        if result:
            alerts_generated = result if isinstance(result, list) else [result]
    except Exception as e:
        # Detection errors should not fail the submission
        pass

    return jsonify({'status': 'ok', 'event_id': event_id, 'alerts': alerts_generated})


@agents_bp.route('/status', methods=['GET'])
@login_required
def agent_status():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, agent_name, ip_address, status, last_seen FROM agents ORDER BY agent_name')
        agents = cursor.fetchall()
        cursor.close()
        conn.close()

        def serialize(row):
            return {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in row.items()}

        return jsonify({'status': 'ok', 'agents': [serialize(a) for a in agents]})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
