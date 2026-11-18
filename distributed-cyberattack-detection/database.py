import hashlib
import os
import re
import sqlite3
from datetime import datetime

from werkzeug.security import generate_password_hash
from config import Config

try:
    import mysql.connector
    HAS_MYSQL = True
except ImportError:
    HAS_MYSQL = False


def _parse_val(val):
    if isinstance(val, str) and len(val) >= 19 and val[4] == '-' and val[7] == '-':
        try:
            return datetime.fromisoformat(val)
        except Exception:
            pass
    return val


class Row(dict):
    """Dictionary-like row that also allows index-based access and .items()."""
    def __init__(self, cols, values):
        parsed = [_parse_val(v) for v in values]
        super().__init__(zip(cols, parsed))
        self._values = tuple(parsed)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class SQLiteCursorWrapper:
    def __init__(self, cursor, dictionary=True):
        self.cursor = cursor
        self.dictionary = dictionary

    def _convert_sql(self, sql):
        # Convert %s placeholders to SQLite ? placeholders
        return re.sub(r'(?<!%)(%s)', '?', sql)

    def execute(self, sql, params=None):
        sql = self._convert_sql(sql)
        if params is None:
            return self.cursor.execute(sql)
        return self.cursor.execute(sql, params)

    def executemany(self, sql, params):
        sql = self._convert_sql(sql)
        return self.cursor.executemany(sql, params)

    def fetchone(self):
        row = self.cursor.fetchone()
        if row is None:
            return None
        cols = [d[0] for d in self.cursor.description]
        return Row(cols, row) if self.dictionary else row

    def fetchall(self):
        rows = self.cursor.fetchall()
        if not rows:
            return []
        cols = [d[0] for d in self.cursor.description]
        return [Row(cols, r) for r in rows] if self.dictionary else rows

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

    @property
    def rowcount(self):
        return self.cursor.rowcount

    def close(self):
        self.cursor.close()


class SQLiteConnectionWrapper:
    def __init__(self, conn, dictionary=True):
        self._conn = conn
        self._use_dict_cursor = dictionary

    def cursor(self, dictionary=None):
        use_dict = self._use_dict_cursor if dictionary is None else dictionary
        return SQLiteCursorWrapper(self._conn.cursor(), dictionary=use_dict)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()


def _get_sqlite_connection(dictionary: bool = True):
    db_path = Config.SQLITE_PATH
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.create_function("NOW", 0, lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return SQLiteConnectionWrapper(conn, dictionary=dictionary)


def get_db_connection(dictionary: bool = True):
    """Return a database connection (MySQL or fallback to SQLite)."""
    if Config.DB_TYPE != "sqlite" and HAS_MYSQL:
        try:
            conn = mysql.connector.connect(
                host=Config.DB_HOST,
                port=Config.DB_PORT,
                database=Config.DB_NAME,
                user=Config.DB_USER,
                password=Config.DB_PASSWORD,
            )
            conn._use_dict_cursor = dictionary
            return conn
        except Exception as e:
            if Config.DB_TYPE == "mysql":
                raise e
            # Auto fallback to SQLite
            return _get_sqlite_connection(dictionary=dictionary)

    return _get_sqlite_connection(dictionary=dictionary)


def _cursor(conn):
    """Return a cursor that respects the dictionary setting on *conn*."""
    use_dict = getattr(conn, "_use_dict_cursor", True)
    return conn.cursor(dictionary=use_dict)


def init_db() -> None:
    """Create all required tables if they do not already exist."""
    conn = get_db_connection(dictionary=False)
    cur = conn.cursor()

    if isinstance(conn, SQLiteConnectionWrapper):
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER      PRIMARY KEY AUTOINCREMENT,
                username      VARCHAR(100) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id               INTEGER      PRIMARY KEY AUTOINCREMENT,
                agent_name       VARCHAR(100) NOT NULL,
                agent_token_hash VARCHAR(255) NOT NULL,
                ip_address       VARCHAR(45)  DEFAULT NULL,
                status           VARCHAR(20)  NOT NULL DEFAULT 'offline',
                last_seen        TIMESTAMP    NULL DEFAULT NULL
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS network_events (
                id               INTEGER     PRIMARY KEY AUTOINCREMENT,
                agent_id         INTEGER     DEFAULT NULL,
                source_ip        VARCHAR(45) DEFAULT NULL,
                destination_ip   VARCHAR(45) DEFAULT NULL,
                protocol         VARCHAR(20) DEFAULT NULL,
                destination_port INTEGER     DEFAULT NULL,
                event_type       VARCHAR(50) DEFAULT NULL,
                timestamp        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE SET NULL
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id          INTEGER      PRIMARY KEY AUTOINCREMENT,
                source_ip   VARCHAR(45)  DEFAULT NULL,
                attack_type VARCHAR(100) DEFAULT NULL,
                severity    VARCHAR(20)  DEFAULT NULL,
                description TEXT         DEFAULT NULL,
                agent_id    INTEGER      DEFAULT NULL,
                detected_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE SET NULL
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER     PRIMARY KEY AUTOINCREMENT,
                attack_id  INTEGER     DEFAULT NULL,
                message    TEXT        DEFAULT NULL,
                severity   VARCHAR(20) DEFAULT NULL,
                status     VARCHAR(20) NOT NULL DEFAULT 'new',
                created_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (attack_id) REFERENCES attacks (id) ON DELETE CASCADE
            );
        """)
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INT          NOT NULL AUTO_INCREMENT,
                username      VARCHAR(100) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                UNIQUE KEY uq_users_username (username)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id               INT          NOT NULL AUTO_INCREMENT,
                agent_name       VARCHAR(100) NOT NULL,
                agent_token_hash VARCHAR(255) NOT NULL,
                ip_address       VARCHAR(45)  DEFAULT NULL,
                status           VARCHAR(20)  NOT NULL DEFAULT 'offline',
                last_seen        TIMESTAMP    NULL DEFAULT NULL,
                PRIMARY KEY (id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS network_events (
                id               INT         NOT NULL AUTO_INCREMENT,
                agent_id         INT         DEFAULT NULL,
                source_ip        VARCHAR(45) DEFAULT NULL,
                destination_ip   VARCHAR(45) DEFAULT NULL,
                protocol         VARCHAR(20) DEFAULT NULL,
                destination_port INT         DEFAULT NULL,
                event_type       VARCHAR(50) DEFAULT NULL,
                timestamp        TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY idx_ne_agent_id  (agent_id),
                KEY idx_ne_source_ip (source_ip),
                KEY idx_ne_timestamp (timestamp),
                CONSTRAINT fk_ne_agent FOREIGN KEY (agent_id)
                    REFERENCES agents (id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id          INT          NOT NULL AUTO_INCREMENT,
                source_ip   VARCHAR(45)  DEFAULT NULL,
                attack_type VARCHAR(100) DEFAULT NULL,
                severity    VARCHAR(20)  DEFAULT NULL,
                description TEXT         DEFAULT NULL,
                agent_id    INT          DEFAULT NULL,
                detected_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY idx_att_agent_id   (agent_id),
                KEY idx_att_source_ip  (source_ip),
                KEY idx_att_attack_type(attack_type),
                CONSTRAINT fk_att_agent FOREIGN KEY (agent_id)
                    REFERENCES agents (id) ON DELETE SET NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id         INT         NOT NULL AUTO_INCREMENT,
                attack_id  INT         DEFAULT NULL,
                message    TEXT        DEFAULT NULL,
                severity   VARCHAR(20) DEFAULT NULL,
                status     VARCHAR(20) NOT NULL DEFAULT 'new',
                created_at TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (id),
                KEY idx_al_attack_id (attack_id),
                KEY idx_al_status    (status),
                CONSTRAINT fk_al_attack FOREIGN KEY (attack_id)
                    REFERENCES attacks (id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)

    conn.commit()
    cur.close()
    conn.close()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def seed_data() -> None:
    """Populate tables with demo data if the database is empty."""
    conn = get_db_connection(dictionary=False)
    cur = conn.cursor()

    # Check if already seeded
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    if count > 0:
        cur.close()
        conn.close()
        return

    # Users
    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
        ('admin', generate_password_hash('admin123')),
    )

    # Agents
    agents = [
        ('Agent-Alpha', _sha256('token-alpha'), '192.168.1.10', 'online',
         datetime(2024, 1, 15, 10, 30, 0)),
        ('Agent-Beta',  _sha256('token-beta'),  '192.168.1.11', 'online',
         datetime(2024, 1, 15, 10, 28, 0)),
        ('Agent-Gamma', _sha256('token-gamma'), '192.168.1.12', 'offline',
         datetime(2024, 1, 14, 22, 15, 0)),
    ]
    cur.executemany(
        """INSERT INTO agents (agent_name, agent_token_hash, ip_address, status, last_seen)
           VALUES (%s, %s, %s, %s, %s)""",
        agents,
    )

    # Network events
    network_events = [
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  22,   'CONNECTION',       datetime(2024, 1, 15, 8,  0,  0)),
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  23,   'CONNECTION',       datetime(2024, 1, 15, 8,  0,  1)),
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  80,   'CONNECTION',       datetime(2024, 1, 15, 8,  0,  2)),
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  443,  'CONNECTION',       datetime(2024, 1, 15, 8,  0,  3)),
        (1, '10.0.0.5',   '192.168.1.10', 'TCP',  8080, 'CONNECTION',       datetime(2024, 1, 15, 8,  0,  4)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5,  0)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5, 10)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5, 20)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5, 30)),
        (2, '172.16.0.3', '192.168.1.11', 'TCP',  22,   'FAILED_LOGIN',     datetime(2024, 1, 15, 9,  5, 40)),
        (1, '203.0.113.1','192.168.1.10', 'UDP',  53,   'HIGH_VOLUME',      datetime(2024, 1, 15, 10, 0,  0)),
        (1, '203.0.113.1','192.168.1.10', 'UDP',  53,   'HIGH_VOLUME',      datetime(2024, 1, 15, 10, 0,  1)),
        (1, '203.0.113.1','192.168.1.10', 'ICMP', None, 'PING_FLOOD',       datetime(2024, 1, 15, 10, 0,  2)),
        (2, '10.10.0.99', '192.168.1.11', 'TCP',  3306, 'CONNECTION',       datetime(2024, 1, 15, 11, 0,  0)),
        (2, '10.10.0.99', '192.168.1.11', 'TCP',  5432, 'CONNECTION',       datetime(2024, 1, 15, 11, 0,  5)),
        (3, '198.51.100.7','192.168.1.12','TCP',  445,  'SMB_PROBE',        datetime(2024, 1, 14, 22, 0,  0)),
        (1, '10.0.0.20',  '192.168.1.10', 'TCP',  21,   'FTP_CONNECT',      datetime(2024, 1, 15, 7, 30,  0)),
        (1, '10.0.0.20',  '192.168.1.10', 'TCP',  25,   'SMTP_CONNECT',     datetime(2024, 1, 15, 7, 31,  0)),
        (2, '192.0.2.50', '192.168.1.11', 'UDP',  161,  'SNMP_PROBE',       datetime(2024, 1, 15, 6,  0,  0)),
        (3, '10.1.1.1',   '192.168.1.12', 'ICMP', None, 'PING',             datetime(2024, 1, 14, 20, 0,  0)),
    ]
    cur.executemany(
        """INSERT INTO network_events
               (agent_id, source_ip, destination_ip, protocol,
                destination_port, event_type, timestamp)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        network_events,
    )

    # Attacks
    attacks = [
        ('10.0.0.5',    'PORT_SCAN',    'high',   'Source IP scanned 12 ports within 60 seconds.',               1, datetime(2024, 1, 15,  8,  1, 0)),
        ('172.16.0.3',  'BRUTE_FORCE',  'critical','5 failed SSH login attempts detected within 60 seconds.',     2, datetime(2024, 1, 15,  9,  5, 45)),
        ('203.0.113.1', 'DOS',          'critical','Over 100 UDP packets/second detected – possible DoS attack.',  1, datetime(2024, 1, 15, 10,  0, 5)),
        ('10.10.0.99',  'SUSPICIOUS_IP','medium',  'IP triggered 50+ events across multiple sensitive ports.',    2, datetime(2024, 1, 15, 11,  1, 0)),
        ('198.51.100.7','PORT_SCAN',    'high',    'Sequential port scan targeting SMB and common Windows ports.', 3, datetime(2024, 1, 14, 22,  5, 0)),
    ]
    cur.executemany(
        """INSERT INTO attacks
               (source_ip, attack_type, severity, description, agent_id, detected_at)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        attacks,
    )

    # Alerts
    alerts = [
        (1, 'Port scan detected from 10.0.0.5 on Agent-Alpha.',           'high',     'new'),
        (2, 'Brute-force SSH attack from 172.16.0.3 on Agent-Beta.',       'critical', 'new'),
        (3, 'DoS attack from 203.0.113.1 targeting Agent-Alpha.',          'critical', 'acknowledged'),
        (4, 'Suspicious activity from 10.10.0.99 on Agent-Beta.',          'medium',   'new'),
        (5, 'Port scan from 198.51.100.7 detected by Agent-Gamma.',        'high',     'new'),
    ]
    cur.executemany(
        """INSERT INTO alerts (attack_id, message, severity, status)
           VALUES (%s, %s, %s, %s)""",
        alerts,
    )

    conn.commit()
    cur.close()
    conn.close()
