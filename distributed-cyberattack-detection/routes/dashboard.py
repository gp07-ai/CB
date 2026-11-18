from functools import wraps
from flask import Blueprint, render_template, session, redirect, url_for, jsonify
from database import get_db_connection

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def _get_dashboard_stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) AS cnt FROM agents')
    total_agents = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) AS cnt FROM agents WHERE status = 'online'")
    active_agents = cursor.fetchone()['cnt']

    cursor.execute('SELECT COUNT(*) AS cnt FROM network_events')
    total_events = cursor.fetchone()['cnt']

    cursor.execute('SELECT COUNT(*) AS cnt FROM attacks')
    total_attacks = cursor.fetchone()['cnt']

    cursor.execute("SELECT COUNT(*) AS cnt FROM alerts WHERE severity = 'CRITICAL' AND status = 'new'")
    critical_alerts = cursor.fetchone()['cnt']

    cursor.execute('''
        SELECT ne.id, ne.source_ip, ne.destination_ip, ne.protocol,
               ne.destination_port, ne.event_type, ne.timestamp,
               a.agent_name
        FROM network_events ne
        LEFT JOIN agents a ON ne.agent_id = a.id
        ORDER BY ne.timestamp DESC
        LIMIT 10
    ''')
    recent_events = cursor.fetchall()

    cursor.execute('''
        SELECT attack_type, COUNT(*) AS count
        FROM attacks
        GROUP BY attack_type
    ''')
    attack_distribution = cursor.fetchall()

    cursor.execute('SELECT id, agent_name, ip_address, status, last_seen FROM agents')
    agent_status = cursor.fetchall()

    cursor.execute('''
        SELECT al.id, al.message, al.severity, al.status, al.created_at,
               at.attack_type, at.source_ip, at.description
        FROM alerts al
        LEFT JOIN attacks at ON al.attack_id = at.id
        ORDER BY al.created_at DESC
        LIMIT 5
    ''')
    recent_alerts = cursor.fetchall()

    cursor.close()
    conn.close()

    class DateTimeStr(str):
        def strftime(self, fmt):
            try:
                return datetime.fromisoformat(self).strftime(fmt)
            except Exception:
                return self

    # Convert datetime objects for JSON serialization
    def serialize(obj):
        if hasattr(obj, 'isoformat'):
            return DateTimeStr(obj.isoformat())
        if isinstance(obj, str) and len(obj) >= 19 and obj[4] == '-' and obj[7] == '-':
            return DateTimeStr(obj)
        return obj

    def serialize_row(row):
        return {k: serialize(v) for k, v in row.items()}

    return {
        'total_agents': total_agents,
        'active_agents': active_agents,
        'total_events': total_events,
        'total_attacks': total_attacks,
        'critical_alerts': critical_alerts,
        'recent_events': [serialize_row(r) for r in recent_events],
        'attack_distribution': [serialize_row(r) for r in attack_distribution],
        'agent_status': [serialize_row(r) for r in agent_status],
        'recent_alerts': [serialize_row(r) for r in recent_alerts],
        'activity_data': [],
    }


@dashboard_bp.route('/')
@login_required
def index():
    try:
        stats = _get_dashboard_stats()
    except Exception as e:
        stats = {
            'total_agents': 0, 'active_agents': 0, 'total_events': 0,
            'total_attacks': 0, 'critical_alerts': 0,
            'recent_events': [], 'attack_distribution': [],
            'agent_status': [], 'recent_alerts': [],
            'error': str(e)
        }
    return render_template('dashboard.html', stats=stats, **stats)


@dashboard_bp.route('/stats')
@login_required
def stats():
    try:
        data = _get_dashboard_stats()
        return jsonify({'status': 'ok', 'data': data})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
