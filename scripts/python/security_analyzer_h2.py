"""
Enhanced Security Event Pattern Analyzer with H2 JDBC Connection
Analyzes authentication events, failed logins, and transaction anomalies
"""

import jaydebeapi
import pandas as pd
from datetime import datetime, timedelta
import json
import sys
import os

class SecurityEventAnalyzer:
    # --- FIX 4: Updated database path to correct relative path from workflow ---
    def __init__(self, db_path='../../ecommerce-app/data/security-events'):
        self.db_url = f"jdbc:h2:{db_path};AUTO_SERVER=TRUE"
        self.db_user = "sa"
        self.db_password = ""
        
        # H2 JDBC driver (needs h2.jar in classpath)
        h2_jar = self._find_h2_jar()
        if h2_jar:
            self.jdbc_driver = "org.h2.Driver"
            self.h2_jar_path = h2_jar
        else:
            print("WARNING: H2 JAR not found. Install h2 database or add h2.jar to classpath")
            self.jdbc_driver = None
        
    def _find_h2_jar(self):
        """Find H2 JAR in Maven local repository"""
        home = os.path.expanduser("~")
        m2_repo = os.path.join(home, ".m2", "repository", "com", "h2database", "h2")
        
        if os.path.exists(m2_repo):
            for version_dir in sorted(os.listdir(m2_repo), reverse=True):
                jar_path = os.path.join(m2_repo, version_dir, f"h2-{version_dir}.jar")
                if os.path.exists(jar_path):
                    return jar_path
        
        return None
    
    def connect(self):
        """Create JDBC connection to H2 database"""
        if not self.jdbc_driver:
            raise Exception("H2 JDBC driver not available")
            
        return jaydebeapi.connect(
            self.jdbc_driver,
            self.db_url,
            [self.db_user, self.db_password],
            self.h2_jar_path
        )
    
    def detect_brute_force_patterns(self, time_window_minutes=30, threshold=5):
        """Detect brute force: multiple failed logins from same user/IP"""
        conn = self.connect()
        cursor = conn.cursor()
        
        query = f"""
            SELECT username, ip_address, COUNT(*) as attempt_count,
                   MIN(attempt_timestamp) as first_attempt,
                   MAX(attempt_timestamp) as last_attempt
            FROM authentication_attempts
            WHERE success = FALSE
              AND attempt_timestamp > DATEADD('MINUTE', -{time_window_minutes}, CURRENT_TIMESTAMP())
            GROUP BY username, ip_address
            HAVING COUNT(*) >= {threshold}
            ORDER BY attempt_count DESC
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        incidents = []
        for row in results:
            incident = {
                'type': 'BRUTE_FORCE_DETECTED',
                'severity': 'HIGH',
                'username': row[0],
                'ip_address': row[1],
                'attempt_count': row[2],
                'time_window': f"{time_window_minutes} minutes",
                'first_attempt': str(row[3]),
                'last_attempt': str(row[4]),
                'recommendation': 'Block IP address, notify security team, require password reset'
            }
            incidents.append(incident)
        
        cursor.close()
        conn.close()
        return incidents
    
    def detect_account_enumeration(self, threshold=10):
        """Detect account enumeration: failed logins across many usernames from same IP"""
        conn = self.connect()
        cursor = conn.cursor()
        
        query = f"""
            SELECT ip_address, COUNT(DISTINCT username) as unique_users,
                   COUNT(*) as total_attempts
            FROM authentication_attempts
            WHERE success = FALSE
              AND attempt_timestamp > DATEADD('HOUR', -1, CURRENT_TIMESTAMP())
            GROUP BY ip_address
            HAVING COUNT(DISTINCT username) >= {threshold}
            ORDER BY unique_users DESC
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        incidents = []
        for row in results:
            incident = {
                'type': 'ACCOUNT_ENUMERATION',
                'severity': 'MEDIUM',
                'ip_address': row[0],
                'unique_usernames_attempted': row[1],
                'total_attempts': row[2],
                'recommendation': 'Block IP, implement CAPTCHA, use generic error messages'
            }
            incidents.append(incident)
        
        cursor.close()
        conn.close()
        return incidents
    
    def detect_transaction_anomalies(self):
        """Detect suspicious transaction patterns"""
        conn = self.connect()
        cursor = conn.cursor()
        
        query = """
            SELECT transaction_id, username, anomaly_type, 
                   original_amount, modified_amount, anomaly_details,
                   detection_timestamp
            FROM transaction_anomalies
            WHERE detection_timestamp > DATEADD('HOUR', -24, CURRENT_TIMESTAMP())
            ORDER BY detection_timestamp DESC
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        incidents = []
        for row in results:
            incident = {
                'type': 'TRANSACTION_ANOMALY',
                'severity': 'HIGH',
                'transaction_id': row[0],
                'username': row[1],
                'anomaly_type': row[2],
                'original_amount': float(row[3]) if row[3] else 0,
                'modified_amount': float(row[4]) if row[4] else 0,
                'details': row[5],
                'timestamp': str(row[6]),
                'recommendation': 'Review transaction, freeze account if necessary'
            }
            incidents.append(incident)
        
        cursor.close()
        conn.close()
        return incidents
    
    def get_high_severity_events(self, hours=24):
        """Get all high-severity security events"""
        conn = self.connect()
        cursor = conn.cursor()
        
        query = f"""
            SELECT event_type, username, ip_address, severity,
                   event_details, suspected_threat, timestamp
            FROM security_events
            WHERE severity = 'HIGH'
              AND timestamp > DATEADD('HOUR', -{hours}, CURRENT_TIMESTAMP())
            ORDER BY timestamp DESC
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        events = []
        for row in results:
            event = {
                'event_type': row[0],
                'username': row[1],
                'ip_address': row[2],
                'severity': row[3],
                'details': row[4],
                'suspected_threat': row[5],
                'timestamp': str(row[6])
            }
            events.append(event)
        
        cursor.close()
        conn.close()
        return events
    
    def generate_incident_report(self):
        """Generate comprehensive incident report"""
        print("=" * 80)
        print("SECURITY INCIDENT ANALYSIS REPORT")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        all_incidents = []
        
        # Detect brute force
        print("\n[1] Analyzing brute force patterns...")
        brute_force = self.detect_brute_force_patterns()
        all_incidents.extend(brute_force)
        print(f"   Found {len(brute_force)} brute force incidents")
        
        # Detect account enumeration
        print("[2] Analyzing account enumeration...")
        enumeration = self.detect_account_enumeration()
        all_incidents.extend(enumeration)
        print(f"   Found {len(enumeration)} enumeration attempts")
        
        # Detect transaction anomalies
        print("[3] Analyzing transaction anomalies...")
        tx_anomalies = self.detect_transaction_anomalies()
        all_incidents.extend(tx_anomalies)
        print(f"   Found {len(tx_anomalies)} transaction anomalies")
        
        # Get high severity events
        print("[4] Retrieving high-severity security events...")
        high_sev = self.get_high_severity_events()
        print(f"   Found {len(high_sev)} high-severity events")
        
        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        
        high_severity = [i for i in all_incidents if i.get('severity') == 'HIGH']
        medium_severity = [i for i in all_incidents if i.get('severity') == 'MEDIUM']
        
        print(f"Total Incidents: {len(all_incidents)}")
        print(f"  - HIGH Severity: {len(high_severity)}")
        print(f"  - MEDIUM Severity: {len(medium_severity)}")
        
        if high_severity:
            print("\n⚠️  CRITICAL: High-severity incidents require immediate attention!")
        
        # Save detailed report
        # --- FIX 3: Removed os.makedirs and changed filename to static name ---
        report_file = "siem_incident_report.json"
        
        with open(report_file, 'w') as f:
            json.dump({
                'generated_at': datetime.now().isoformat(),
                'total_incidents': len(all_incidents),
                'high_severity_count': len(high_severity),
                'medium_severity_count': len(medium_severity),
                'incidents': all_incidents,
                'high_severity_events': high_sev
            }, f, indent=2)
        
        print(f"\nDetailed report saved to: {os.path.abspath(report_file)}")
        
        return all_incidents

if __name__ == "__main__":
    try:
        analyzer = SecurityEventAnalyzer()
        incidents = analyzer.generate_incident_report()
        
        # Exit with error code if high-severity incidents found
        high_severity_count = len([i for i in incidents if i.get('severity') == 'HIGH'])
        sys.exit(1 if high_severity_count > 0 else 0)
        
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        print("\nNote: Ensure the e-commerce application has been run to create the database.")
        print("Run: cd ecommerce-app && mvn spring-boot:run")
        sys.exit(2)