import io
import csv
from functools import wraps
from flask import Blueprint, request, session, redirect, url_for, jsonify, Response
from database import get_db_connection

events_bp = Blueprint('events', __name__, url_prefix='/api/events')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def serialize_row(row):
    return {k: (v.isoformat() if hasattr(v, 'isoformat') else v) for k, v in row.items()}


@events_bp.route('/', methods=['GET'])
@login_required
def list_events():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    source_ip = request.args.get('source_ip', '').strip()
    protocol = request.args.get('protocol', '').strip()
    event_type = request.args.get('event_type', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()

    if page < 1:
        page = 1
    if per_page < 1 or per_page > 500:
        per_page = 20

    offset = (page - 1) * per_page

    conditions = []
    params = []

    if source_ip:
        conditions.append('ne.source_ip LIKE %s')
        params.append(f'%{source_ip}%')
    if protocol:
        conditions.append('ne.protocol = %s')
        params.append(protocol)
    if event_type:
        conditions.append('ne.event_type = %s')
        params.append(event_type)
    if date_from:
        conditions.append('ne.timestamp >= %s')
        params.append(date_from)
    if date_to:
        conditions.append('ne.timestamp <= %s')
        params.append(date_to)

    where_clause = ('WHERE ' + ' AND '.join(conditions)) if conditions else ''

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        count_query = f'SELECT COUNT(*) AS cnt FROM network_events ne {where_clause}'
        cursor.execute(count_query, params)
        total = cursor.fetchone()['cnt']

        data_query = f'''
            SELECT ne.id, ne.source_ip, ne.destination_ip, ne.protocol,
                   ne.destination_port, ne.event_type, ne.timestamp,
                   a.agent_name
            FROM network_events ne
            LEFT JOIN agents a ON ne.agent_id = a.id
            {where_clause}
            ORDER BY ne.timestamp DESC
            LIMIT %s OFFSET %s
        '''
        cursor.execute(data_query, params + [per_page, offset])
        events = cursor.fetchall()
        cursor.close()
        conn.close()

        return jsonify({
            'status': 'ok',
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page,
            'events': [serialize_row(e) for e in events]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@events_bp.route('/<int:event_id>', methods=['GET'])
@login_required
def get_event(event_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ne.id, ne.source_ip, ne.destination_ip, ne.protocol,
                   ne.destination_port, ne.event_type, ne.timestamp,
                   a.agent_name, a.ip_address AS agent_ip
            FROM network_events ne
            LEFT JOIN agents a ON ne.agent_id = a.id
            WHERE ne.id = %s
        ''', (event_id,))
        event = cursor.fetchone()
        cursor.close()
        conn.close()

        if not event:
            return jsonify({'status': 'error', 'message': 'Event not found'}), 404

        return jsonify({'status': 'ok', 'event': serialize_row(event)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@events_bp.route('/export', methods=['GET'])
@login_required
def export_events():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ne.id, ne.source_ip, ne.destination_ip, ne.protocol,
                   ne.destination_port, ne.event_type, ne.timestamp,
                   a.agent_name
            FROM network_events ne
            LEFT JOIN agents a ON ne.agent_id = a.id
            ORDER BY ne.timestamp DESC
        ''')
        events = cursor.fetchall()
        cursor.close()
        conn.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Source IP', 'Destination IP', 'Protocol',
                         'Destination Port', 'Event Type', 'Timestamp', 'Agent Name'])

        for e in events:
            writer.writerow([
                e['id'], e['source_ip'], e['destination_ip'], e['protocol'],
                e['destination_port'], e['event_type'],
                e['timestamp'].isoformat() if hasattr(e['timestamp'], 'isoformat') else e['timestamp'],
                e['agent_name']
            ])

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=network_events.csv'}
        )
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
