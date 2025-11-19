import json
import os
from typing import List, Dict, Optional
from datetime import datetime

try:
    import psycopg2
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

class DatabaseManager:
    def __init__(self):
        if not PSYCOPG2_AVAILABLE:
            self.db_available = False
            return
        
        self.connection_params = {
            'dbname': os.getenv('PGDATABASE'),
            'user': os.getenv('PGUSER'),
            'password': os.getenv('PGPASSWORD'),
            'host': os.getenv('PGHOST'),
            'port': os.getenv('PGPORT')
        }
        self.db_available = self._check_database_available()
    
    def _check_database_available(self) -> bool:
        if not PSYCOPG2_AVAILABLE or not all(self.connection_params.values()):
            return False
        try:
            if PSYCOPG2_AVAILABLE:
                conn = psycopg2.connect(**self.connection_params)
                conn.close()
            return True
        except Exception:
            return False
    
    def get_connection(self):
        if not self.db_available or not PSYCOPG2_AVAILABLE:
            raise ConnectionError("Database not available")
        if PSYCOPG2_AVAILABLE:
            return psycopg2.connect(**self.connection_params)
        raise ConnectionError("psycopg2 not installed")
    
    def save_analysis(self, filename: str, total_lines: int, total_attacks: int, 
                     unique_ips: int, attack_breakdown: Dict, attacks_data: List[Dict]) -> int:
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO analysis_history 
                    (filename, total_lines, total_attacks, unique_ips, attack_breakdown, attacks_data)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (filename, total_lines, total_attacks, unique_ips, 
                      json.dumps(attack_breakdown), json.dumps(attacks_data)))
                analysis_id = cursor.fetchone()[0]
                conn.commit()
                return analysis_id
        finally:
            conn.close()
    
    def get_analysis_history(self, limit: int = 50) -> List[Dict]:
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id, filename, total_lines, total_attacks, unique_ips, 
                           attack_breakdown, analyzed_at
                    FROM analysis_history
                    ORDER BY analyzed_at DESC
                    LIMIT %s
                """, (limit,))
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'id': row[0],
                        'filename': row[1],
                        'total_lines': row[2],
                        'total_attacks': row[3],
                        'unique_ips': row[4],
                        'attack_breakdown': row[5],
                        'analyzed_at': row[6]
                    })
                return results
        finally:
            conn.close()
    
    def get_timeline_data(self, days: int = 30) -> List[Dict]:
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT DATE(analyzed_at) as date,
                           SUM(total_attacks) as attacks,
                           SUM(unique_ips) as unique_ips,
                           attack_breakdown
                    FROM analysis_history
                    WHERE analyzed_at >= NOW() - INTERVAL '%s days'
                    GROUP BY DATE(analyzed_at), attack_breakdown
                    ORDER BY date
                """, (days,))
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'date': str(row[0]),
                        'attacks': row[1],
                        'unique_ips': row[2],
                        'attack_breakdown': row[3]
                    })
                return results
        finally:
            conn.close()
    
    def add_custom_pattern(self, attack_type: str, pattern_regex: str, 
                          description: str = "") -> int:
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO custom_patterns (attack_type, pattern_regex, description)
                    VALUES (%s, %s, %s)
                    RETURNING id
                """, (attack_type, pattern_regex, description))
                pattern_id = cursor.fetchone()[0]
                conn.commit()
                return pattern_id
        finally:
            conn.close()
    
    def get_custom_patterns(self, active_only: bool = True) -> List[Dict]:
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                if active_only:
                    cursor.execute("""
                        SELECT id, attack_type, pattern_regex, description, is_active, created_at
                        FROM custom_patterns
                        WHERE is_active = TRUE
                        ORDER BY attack_type, created_at
                    """)
                else:
                    cursor.execute("""
                        SELECT id, attack_type, pattern_regex, description, is_active, created_at
                        FROM custom_patterns
                        ORDER BY attack_type, created_at
                    """)
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'id': row[0],
                        'attack_type': row[1],
                        'pattern_regex': row[2],
                        'description': row[3],
                        'is_active': row[4],
                        'created_at': row[5]
                    })
                return results
        finally:
            conn.close()
    
    def update_custom_pattern(self, pattern_id: int, attack_type: str = None, 
                             pattern_regex: str = None, description: str = None,
                             is_active: bool = None):
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                updates = []
                params = []
                
                if attack_type is not None:
                    updates.append("attack_type = %s")
                    params.append(attack_type)
                if pattern_regex is not None:
                    updates.append("pattern_regex = %s")
                    params.append(pattern_regex)
                if description is not None:
                    updates.append("description = %s")
                    params.append(description)
                if is_active is not None:
                    updates.append("is_active = %s")
                    params.append(is_active)
                
                updates.append("updated_at = CURRENT_TIMESTAMP")
                params.append(pattern_id)
                
                cursor.execute(f"""
                    UPDATE custom_patterns
                    SET {', '.join(updates)}
                    WHERE id = %s
                """, params)
                conn.commit()
        finally:
            conn.close()
    
    def delete_custom_pattern(self, pattern_id: int):
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM custom_patterns WHERE id = %s", (pattern_id,))
                conn.commit()
        finally:
            conn.close()
    
    def track_unknown_attack(self, url: str, ip: str, timestamp: str, 
                            method: str, user_agent: str):
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO unknown_attacks (url, ip, timestamp, method, user_agent)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (url, ip)
                    DO UPDATE SET frequency = unknown_attacks.frequency + 1,
                                  detected_at = CURRENT_TIMESTAMP
                """, (url, ip, timestamp, method, user_agent))
                conn.commit()
        finally:
            conn.close()
    
    def get_unknown_attacks(self, limit: int = 100) -> List[Dict]:
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT id, url, ip, timestamp, method, user_agent, detected_at, frequency
                    FROM unknown_attacks
                    ORDER BY frequency DESC, detected_at DESC
                    LIMIT %s
                """, (limit,))
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'id': row[0],
                        'url': row[1],
                        'ip': row[2],
                        'timestamp': row[3],
                        'method': row[4],
                        'user_agent': row[5],
                        'detected_at': row[6],
                        'frequency': row[7]
                    })
                return results
        finally:
            conn.close()
    
    def clear_unknown_attacks(self):
        conn = self.get_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM unknown_attacks")
                conn.commit()
        finally:
            conn.close()
