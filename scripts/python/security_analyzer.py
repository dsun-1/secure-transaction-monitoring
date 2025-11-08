"""
Security Event Pattern Analyzer
Analyzes authentication events, failed logins, and transaction anomalies
to detect brute-force behavior, suspicious patterns, and security threats.
"""

import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
import json
import sys

class SecurityEventAnalyzer:
    def __init__(self, db_path='./data/security-events.mv.db'):
        # H2 database - use JDBC or export to SQLite for Python analysis
        # For this example, assuming exported or compatible SQLite format
        self.db_path = db_path.replace('.mv.db', '.db')
        
    def connect(self):
        return sqlite3.connect(self.db_path)
    
    def detect_brute_force_patterns(self, time_window_minutes=30, threshold=5):
        """
        Detect brute force attempts: multiple failed logins from same user/IP
        within a short time window.
        """
        conn = self.connect()
        query = """
            SELECT username, ip_address, COUNT(*) as attempt_count,
                   MIN(attempt_timestamp) as first_attempt,
                   MAX(attempt_timestamp) as last_attempt
            FROM authentication_attempts
            WHERE success = 0
              AND attempt_timestamp > datetime('now', '-{} minutes')
            GROUP BY username, ip_address
            HAVING COUNT(*) >= {}
            ORDER BY attempt_count DESC
        """.format(time_window_minutes, threshold)
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        incidents = []
        for _, row in df.iterrows():
            incident = {
                'type': 'BRUTE_FORCE_DETECTED',
                'severity': 'HIGH',
                'username': row['username'],
                'ip_address': row['ip_address'],
                'attempt_count': row['attempt_count'],
                'time_window': f"{time_window_minutes} minutes",
                'first_attempt': row['first_attempt'],
                'last_attempt': row['last_attempt'],
                'recommendation': 'Block IP address temporarily, notify security team, require password reset'
            }
            incidents.append(incident)
        
        return incidents
    
    def detect_account_enumeration(self, threshold=10):
        """
        Detect account enumeration: Failed login attempts across many different usernames
        from same IP address.
        """
        conn = self.connect()
        query = """
            SELECT ip_address, COUNT(DISTINCT username) as unique_users,
                   COUNT(*) as total_attempts
            FROM authentication_attempts
            WHERE success = 0
              AND attempt_timestamp > datetime('now', '-1 hour')
            GROUP BY ip_address
            HAVING COUNT(DISTINCT username) >= {}
            ORDER BY unique_users DESC
        """.format(threshold)
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        incidents = []
        for _, row in df.iterrows():
            incident = {
                'type': 'ACCOUNT_ENUMERATION',
                'severity': 'MEDIUM',
                'ip_address': row['ip_address'],
                'unique_usernames_attempted': row['unique_users'],
                'total_attempts': row['total_attempts'],
                'recommendation': 'Block IP, implement CAPTCHA, use generic error messages'
            }
            incidents.append(incident)
        
        return incidents
    
    def detect_privilege_escalation_attempts(self):
        """
        Detect potential privilege escalation by analyzing security events.
        """
        conn = self.connect()
        query = """
            SELECT * FROM security_events
            WHERE event_type IN ('PRIVILEGE_ESCALATION', 'UNAUTHORIZED_ACCESS', 'ADMIN_ACCESS_ATTEMPT')
              AND timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
        """
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        incidents = []
        for _, row in df.iterrows():
            incident = {
                'type': 'PRIVILEGE_ESCALATION_ATTEMPT',
                'severity': row['severity'],
                'username': row['username'],
                'session_id': row['session_id'],
                'event_details': row['event_details'],
                'timestamp': row['timestamp'],
                'recommendation': 'Review user permissions, audit account activity, potential account compromise'
            }
            incidents.append(incident)
        
        return incidents
    
    def analyze_transaction_anomalies(self):
        """
        Analyze transaction anomalies for patterns of fraud or tampering.
        """
        conn = self.connect()
        query = """
            SELECT anomaly_type, username, COUNT(*) as occurrence_count,
                   AVG(ABS(modified_amount - original_amount)) as avg_difference,
                   MAX(detection_timestamp) as latest_occurrence
            FROM transaction_anomalies
            WHERE detection_timestamp > datetime('now', '-7 days')
            GROUP BY anomaly_type, username
            ORDER BY occurrence_count DESC
        """
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        incidents = []
        for _, row in df.iterrows():
            severity = 'HIGH' if row['occurrence_count'] >= 3 else 'MEDIUM'
            incident = {
                'type': 'TRANSACTION_ANOMALY_PATTERN',
                'severity': severity,
                'anomaly_type': row['anomaly_type'],
                'username': row['username'],
                'occurrence_count': row['occurrence_count'],
                'avg_price_difference': round(row['avg_difference'], 2),
                'latest_occurrence': row['latest_occurrence'],
                'recommendation': 'Flag account for manual review, implement additional verification for this user'
            }
            incidents.append(incident)
        
        return incidents
    
    def detect_suspicious_time_patterns(self):
        """
        Detect logins or transactions at unusual times (e.g., 2-5 AM).
        """
        conn = self.connect()
        query = """
            SELECT username, 
                   strftime('%H', attempt_timestamp) as hour,
                   COUNT(*) as activity_count
            FROM authentication_attempts
            WHERE success = 1
              AND CAST(strftime('%H', attempt_timestamp) AS INTEGER) BETWEEN 2 AND 5
              AND attempt_timestamp > datetime('now', '-30 days')
            GROUP BY username, hour
            HAVING COUNT(*) >= 3
        """
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        
        incidents = []
        for _, row in df.iterrows():
            incident = {
                'type': 'UNUSUAL_TIME_ACTIVITY',
                'severity': 'MEDIUM',
                'username': row['username'],
                'hour': row['hour'],
                'activity_count': row['activity_count'],
                'recommendation': 'Verify if legitimate user behavior, potential compromised account'
            }
            incidents.append(incident)
        
        return incidents
    
    def generate_incident_report(self):
        """
        Generate comprehensive incident report with all detected threats.
        """
        print("=" * 80)
        print("SECURITY INCIDENT DETECTION REPORT")
        print("Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print("=" * 80)
        
        all_incidents = []
        
        # Detect brute force
        print("\n[1] Detecting Brute Force Attacks...")
        brute_force = self.detect_brute_force_patterns()
        all_incidents.extend(brute_force)
        print(f"   Found {len(brute_force)} brute force incidents")
        
        # Detect account enumeration
        print("\n[2] Detecting Account Enumeration...")
        enumeration = self.detect_account_enumeration()
        all_incidents.extend(enumeration)
        print(f"   Found {len(enumeration)} enumeration attempts")
        
        # Detect privilege escalation
        print("\n[3] Detecting Privilege Escalation Attempts...")
        priv_esc = self.detect_privilege_escalation_attempts()
        all_incidents.extend(priv_esc)
        print(f"   Found {len(priv_esc)} privilege escalation attempts")
        
        # Analyze transaction anomalies
        print("\n[4] Analyzing Transaction Anomalies...")
        tx_anomalies = self.analyze_transaction_anomalies()
        all_incidents.extend(tx_anomalies)
        print(f"   Found {len(tx_anomalies)} transaction anomaly patterns")
        
        # Detect suspicious timing
        print("\n[5] Detecting Suspicious Time Patterns...")
        time_patterns = self.detect_suspicious_time_patterns()
        all_incidents.extend(time_patterns)
        print(f"   Found {len(time_patterns)} unusual time activities")
        
        print("\n" + "=" * 80)
        print(f"TOTAL INCIDENTS DETECTED: {len(all_incidents)}")
        print("=" * 80)
        
        # Categorize by severity
        high_severity = [i for i in all_incidents if i.get('severity') == 'HIGH']
        medium_severity = [i for i in all_incidents if i.get('severity') == 'MEDIUM']
        
        print(f"\nHIGH Severity: {len(high_severity)}")
        print(f"MEDIUM Severity: {len(medium_severity)}")
        
        # Save detailed report
        report_file = f"security_incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'generated_at': datetime.now().isoformat(),
                'total_incidents': len(all_incidents),
                'high_severity_count': len(high_severity),
                'medium_severity_count': len(medium_severity),
                'incidents': all_incidents
            }, f, indent=2)
        
        print(f"\nDetailed report saved to: {report_file}")
        
        return all_incidents

if __name__ == "__main__":
    analyzer = SecurityEventAnalyzer()
    incidents = analyzer.generate_incident_report()
    
    # Exit with error code if high-severity incidents found
    high_severity_count = len([i for i in incidents if i.get('severity') == 'HIGH'])
    sys.exit(1 if high_severity_count > 0 else 0)
