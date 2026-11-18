import io
import csv
from functools import wraps
from flask import Blueprint, request, session, redirect, url_for, jsonify, Response
from database import get_db_connection

alerts_bp = Blueprint('alerts', __name__, url_prefix='/api/alerts')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def serialize_row(row):
    return {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in row.items()}


# ─── Alerts ───────────────────────────────────────────────────────────────────

@alerts_bp.route('/', methods=['GET'])
@login_required
def list_alerts():
    status_filter = request.args.get('status', '').strip()
    severity_filter = request.args.get('severity', '').strip()

    conditions = []
    params = []
    if status_filter:
        conditions.append('al.status = %s')
        params.append(status_filter)
    if severity_filter:
        conditions.append('al.severity = %s')
        params.append(severity_filter)

    where_clause = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(f'''
            SELECT al.id, al.message, al.severity, al.status, al.created_at,
                   at.attack_type, at.source_ip, at.description, at.detected_at
            FROM alerts al
            LEFT JOIN attacks at ON al.attack_id = at.id
            {where_clause}
            ORDER BY al.created_at DESC
        ''', params)
        alerts = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'status': 'ok', 'alerts': [serialize_row(a) for a in alerts]})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@alerts_bp.route('/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE alerts SET status = 'acknowledged' WHERE id = %s",
            (alert_id,)
        )
        affected = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        if affected == 0:
            return jsonify({'status': 'error', 'message': 'Alert not found'}), 404
        return jsonify({'status': 'ok', 'alert_id': alert_id, 'new_status': 'acknowledged'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─── Attacks ──────────────────────────────────────────────────────────────────

@alerts_bp.route('/attacks', methods=['GET'])
@login_required
def list_attacks():
    attack_type = request.args.get('attack_type', '').strip()
    severity = request.args.get('severity', '').strip()
    source_ip = request.args.get('source_ip', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    conditions = []
    params = []
    if attack_type:
        conditions.append('attack_type = %s')
        params.append(attack_type)
    if severity:
        conditions.append('severity = %s')
        params.append(severity)
    if source_ip:
        conditions.append('source_ip LIKE %s')
        params.append(f'%{source_ip}%')
    if date_from:
        conditions.append('detected_at >= %s')
        params.append(date_from)
    if date_to:
        conditions.append('detected_at <= %s')
        params.append(date_to)

    where_clause = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(f'''
            SELECT id, source_ip, attack_type, severity, description, agent_id, detected_at
            FROM attacks
            {where_clause}
            ORDER BY detected_at DESC
        ''', params)
        attacks = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'status': 'ok', 'attacks': [serialize_row(a) for a in attacks]})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@alerts_bp.route('/attacks/export', methods=['GET'])
@login_required
def export_attacks():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, source_ip, attack_type, severity, description, agent_id, detected_at FROM attacks ORDER BY detected_at DESC')
        attacks = cursor.fetchall()
        cursor.close()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Source IP', 'Attack Type', 'Severity', 'Description', 'Agent ID', 'Detected At'])
        for a in attacks:
            writer.writerow([
                a['id'], a['source_ip'], a['attack_type'], a['severity'],
                a['description'], a['agent_id'],
                a['detected_at'].isoformat() if hasattr(a['detected_at'], 'isoformat') else a['detected_at']
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=attacks.csv'}
        )
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ─── Logs ─────────────────────────────────────────────────────────────────────

@alerts_bp.route('/logs', methods=['GET'])
@login_required
def list_logs():
    """Return combined security logs: events + attacks + alerts merged, sorted by time."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, 'event' AS log_type, source_ip, event_type AS detail,
                   NULL AS severity, timestamp AS log_time
            FROM network_events
        ''')
        events = cursor.fetchall()

        cursor.execute('''
            SELECT id, 'attack' AS log_type, source_ip, attack_type AS detail,
                   severity, detected_at AS log_time
            FROM attacks
        ''')
        attacks = cursor.fetchall()

        cursor.execute('''
            SELECT al.id, 'alert' AS log_type, at.source_ip, al.message AS detail,
                   al.severity, al.created_at AS log_time
            FROM alerts al
            LEFT JOIN attacks at ON al.attack_id = at.id
        ''')
        alert_rows = cursor.fetchall()

        cursor.close()
        conn.close()

        combined = [serialize_row(r) for r in (list(events) + list(attacks) + list(alert_rows))]
        combined.sort(key=lambda x: x.get('log_time') or '', reverse=True)

        return jsonify({'status': 'ok', 'logs': combined, 'total': len(combined)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@alerts_bp.route('/logs/export', methods=['GET'])
@login_required
def export_logs():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, 'event' AS log_type, source_ip, event_type AS detail,
                   NULL AS severity, timestamp AS log_time
            FROM network_events
        ''')
        events = cursor.fetchall()

        cursor.execute('''
            SELECT id, 'attack' AS log_type, source_ip, attack_type AS detail,
                   severity, detected_at AS log_time
            FROM attacks
        ''')
        attacks = cursor.fetchall()

        cursor.execute('''
            SELECT al.id, 'alert' AS log_type, at.source_ip, al.message AS detail,
                   al.severity, al.created_at AS log_time
            FROM alerts al
            LEFT JOIN attacks at ON al.attack_id = at.id
        ''')
        alert_rows = cursor.fetchall()

        cursor.close()
        conn.close()

        combined = [serialize_row(r) for r in (list(events) + list(attacks) + list(alert_rows))]
        combined.sort(key=lambda x: x.get('log_time') or '', reverse=True)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Log Type', 'Source IP', 'Detail', 'Severity', 'Time'])
        for row in combined:
            writer.writerow([
                row.get('id'), row.get('log_type'), row.get('source_ip'),
                row.get('detail'), row.get('severity'), row.get('log_time')
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=security_logs.csv'}
        )
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
