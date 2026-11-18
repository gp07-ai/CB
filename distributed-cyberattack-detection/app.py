from flask import Flask, session, redirect, url_for, render_template
from config import Config
from database import init_db, seed_data
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.agents import agents_bp
from routes.events import events_bp
from routes.alerts import alerts_bp

app = Flask(__name__)
app.config.from_object(Config)

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
app.register_blueprint(agents_bp, url_prefix='/api/agents')
app.register_blueprint(events_bp, url_prefix='/api/events')
app.register_blueprint(alerts_bp, url_prefix='/api/alerts')


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
    return redirect(url_for('auth.login'))


@app.context_processor
def inject_user():
    return {'current_user': session.get('username', None)}


if __name__ == '__main__':
    with app.app_context():
        init_db()
        seed_data()
    app.run(host='0.0.0.0', port=5000, debug=True)
