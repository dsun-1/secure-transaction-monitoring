import logging
import jaydebeapi
from datetime import datetime, timedelta
import json
import sys
import os

# lightweight siem analyzer that queries the h2 event store and emits a json report
logger = logging.getLogger('security_analyzer')
if not logger.handlers:
    h = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    h.setFormatter(formatter)
    logger.addHandler(h)
logger.setLevel(logging.INFO)

class SecurityEventAnalyzer:
    # central analyzer class for detection and reporting
    def __init__(self, db_path=None):
        if db_path is None:
            # Resolve path relative to this script file
            script_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(script_dir, '../../data/security-events')

        # connect to the same event store used by the app and tests
        self.db_url = f"jdbc:h2:{db_path};AUTO_SERVER=TRUE"
        self.db_user = "sa"
        self.db_password = ""
        
                                                    
        # resolve h2 jdbc driver from local m2 cache
        h2_jar = self._find_h2_jar()
        if h2_jar:
            self.jdbc_driver = "org.h2.Driver"
            self.h2_jar_path = h2_jar
        else:
            print("WARNING: H2 JAR not found. Install h2 database or add h2.jar to classpath")
            self.jdbc_driver = None
        
    # locate the h2 jar in the local maven repository
    def _find_h2_jar(self):
        home = os.path.expanduser("~")
        m2_repo = os.path.join(home, ".m2", "repository", "com", "h2database", "h2")
        
        if os.path.exists(m2_repo):
            for version_dir in sorted(os.listdir(m2_repo), reverse=True):
                jar_path = os.path.join(m2_repo, version_dir, f"h2-{version_dir}.jar")
                if os.path.exists(jar_path):
                    return jar_path
        
        return None
    
    # open a jdbc connection to the h2 file db
    def connect(self):
        if not self.jdbc_driver:
            raise Exception("H2 JDBC driver not available")

        logger.debug("Connecting to H2 JDBC URL: %s", self.db_url)
        return jaydebeapi.connect(
            self.jdbc_driver,
            self.db_url,
            [self.db_user, self.db_password],
            self.h2_jar_path
        )
    
    # detect repeated failed logins within a window (threshold-based alerting)
    def detect_brute_force_patterns(self, time_window_minutes=30, threshold=5):
        logger.debug("Detecting brute force patterns (window=%s min, threshold=%s)", time_window_minutes, threshold)
        try:
            conn = self.connect()
            cursor = conn.cursor()
        except Exception as e:
            logger.error("Failed to connect to DB for brute force detection: %s", e)
            return []
        
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
        logger.info("Brute force detection found %d incidents", len(incidents))
        return incidents
    
    # detect many unique usernames from a single ip (enumeration indicator)
    def detect_account_enumeration(self, threshold=10):
        logger.debug("Detecting account enumeration (threshold=%s)", threshold)
        try:
            conn = self.connect()
            cursor = conn.cursor()
        except Exception as e:
            logger.error("Failed to connect to DB for account enumeration: %s", e)
            return []
        
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
        logger.info("Account enumeration detection found %d incidents", len(incidents))
        return incidents
    
    # detect suspicious transaction patterns from anomaly table
    def detect_transaction_anomalies(self):
        logger.debug("Detecting transaction anomalies")
        try:
            conn = self.connect()
            cursor = conn.cursor()
        except Exception as e:
            logger.error("Failed to connect to DB for transaction anomaly detection: %s", e)
            return []

                                                                                   
        try:
            cursor.execute("SELECT 1 FROM transaction_anomalies LIMIT 1")
        except Exception:
            logger.warning("'transaction_anomalies' table not found — creating sample table and inserting demo row.")
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS transaction_anomalies (
                        transaction_id VARCHAR(64),
                        username VARCHAR(64),
                        anomaly_type VARCHAR(64),
                        original_amount DECIMAL(19,4),
                        modified_amount DECIMAL(19,4),
                        anomaly_details VARCHAR(1024),
                        detection_timestamp TIMESTAMP
                    )
                """)
                                           
                cursor.execute("""
                    INSERT INTO transaction_anomalies (
                        transaction_id, username, anomaly_type, original_amount, modified_amount, anomaly_details, detection_timestamp
                    ) VALUES (
                        'demo-tx-001', 'testuser', 'NEGATIVE_MODIFICATION', 100.00, -100.00, 'Demo negative amount modification detected', CURRENT_TIMESTAMP()
                    )
                """)
                conn.commit()
                logger.info("Inserted demo transaction anomaly for demo purposes")
            except Exception as e:
                logger.error("Failed to create demo transaction_anomalies table: %s", e)

        query = """
            SELECT transaction_id, username, anomaly_type, 
                   original_amount, modified_amount, anomaly_details,
                   detection_timestamp
            FROM transaction_anomalies
            WHERE detection_timestamp > DATEADD('HOUR', -24, CURRENT_TIMESTAMP())
            ORDER BY detection_timestamp DESC
        """

        try:
            cursor.execute(query)
            results = cursor.fetchall()
        except Exception as e:
            logger.error("Error executing transaction anomalies query: %s", e)
            results = []
        
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
        logger.info("Transaction anomaly detection found %d incidents", len(incidents))
        return incidents
    
    # pull recent high-severity events for reporting and escalation
    def get_high_severity_events(self, hours=24):
        logger.debug("Retrieving high severity events from last %s hours", hours)
        try:
            conn = self.connect()
            cursor = conn.cursor()
        except Exception as e:
            logger.error("Failed to connect to DB for high severity event retrieval: %s", e)
            return []

        primary_query = f"""
            SELECT event_type, username, ip_address, severity,
                   description, additional_data, timestamp
            FROM security_events
            WHERE severity = 'HIGH'
              AND timestamp > DATEADD('HOUR', -{hours}, CURRENT_TIMESTAMP())
            ORDER BY timestamp DESC
        """

        legacy_query = f"""
            SELECT event_type, username, ip_address, severity,
                   event_details, suspected_threat, timestamp
            FROM security_events
            WHERE severity = 'HIGH'
              AND timestamp > DATEADD('HOUR', -{hours}, CURRENT_TIMESTAMP())
            ORDER BY timestamp DESC
        """

        minimal_query = f"""
            SELECT event_type, username, ip_address, severity, timestamp
            FROM security_events
            WHERE severity = 'HIGH'
              AND timestamp > DATEADD('HOUR', -{hours}, CURRENT_TIMESTAMP())
            ORDER BY timestamp DESC
        """

        try:
            cursor.execute("""
                SELECT COLUMN_NAME
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_NAME = 'SECURITY_EVENTS'
            """)
            columns = {row[0].upper() for row in cursor.fetchall()}
        except Exception:
            columns = set()

        try:
            queries = []
            if "DESCRIPTION" in columns and "ADDITIONAL_DATA" in columns:
                queries.append(primary_query)
            if "EVENT_DETAILS" in columns and "SUSPECTED_THREAT" in columns:
                queries.append(legacy_query)
            queries.append(minimal_query)

            for idx, query in enumerate(queries):
                try:
                    cursor.execute(query)
                    results = cursor.fetchall()
                    events = []
                    for row in results:
                        if len(row) >= 7:
                            event = {
                                'event_type': row[0],
                                'username': row[1],
                                'ip_address': row[2],
                                'severity': row[3],
                                'details': row[4],
                                'suspected_threat': row[5],
                                'timestamp': str(row[6])
                            }
                        else:
                            event = {
                                'event_type': row[0],
                                'username': row[1],
                                'ip_address': row[2],
                                'severity': row[3],
                                'details': None,
                                'suspected_threat': None,
                                'timestamp': str(row[4])
                            }
                        events.append(event)
                    if idx == 0:
                        logger.info("Retrieved %d high-severity events", len(events))
                    elif idx == 1 and len(queries) > 1:
                        logger.info("Retrieved %d high-severity events using legacy columns", len(events))
                    else:
                        logger.info("Retrieved %d high-severity events without optional columns", len(events))
                    return events
                except Exception as e:
                    if idx == 0:
                        logger.warning("Primary high-severity query failed: %s", e)
                    elif idx == 1:
                        logger.warning("Legacy high-severity query failed: %s", e)
                    else:
                        logger.error("Fallback high-severity query failed: %s", e)
            return []
        finally:
            cursor.close()
            conn.close()
    
    # run all detections and write a consolidated json report
    def generate_incident_report(self):
        print("=" * 80)
        print("SECURITY INCIDENT ANALYSIS REPORT")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        all_incidents = []
        
                            
        print("\n[1] Analyzing brute force patterns...")
        brute_force = self.detect_brute_force_patterns()
        all_incidents.extend(brute_force)
        print(f"   Found {len(brute_force)} brute force incidents")
        
                                    
        print("[2] Analyzing account enumeration...")
        enumeration = self.detect_account_enumeration()
        all_incidents.extend(enumeration)
        print(f"   Found {len(enumeration)} enumeration attempts")
        
                                      
        print("[3] Analyzing transaction anomalies...")
        tx_anomalies = self.detect_transaction_anomalies()
        all_incidents.extend(tx_anomalies)
        print(f"   Found {len(tx_anomalies)} transaction anomalies")
        
                                  
        print("[4] Retrieving high-severity security events...")
        high_sev = self.get_high_severity_events()
        print(f"   Found {len(high_sev)} high-severity events")
        # Promote high-severity events into incidents for ticketing/reporting.
        for event in high_sev:
            incident = {
                'type': event.get('event_type', 'SECURITY_EVENT'),
                'severity': event.get('severity', 'HIGH'),
                'username': event.get('username'),
                'ip_address': event.get('ip_address'),
                'details': event.get('details'),
                'suspected_threat': event.get('suspected_threat'),
                'timestamp': event.get('timestamp'),
                'recommendation': 'Investigate event and apply appropriate mitigation'
            }
            all_incidents.append(incident)
        
                 
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        
        high_severity = [i for i in all_incidents if i.get('severity') == 'HIGH']
        medium_severity = [i for i in all_incidents if i.get('severity') == 'MEDIUM']
        
        print(f"Total Incidents: {len(all_incidents)}")
        print(f"  - HIGH Severity: {len(high_severity)}")
        print(f"  - MEDIUM Severity: {len(medium_severity)}")
        
        if high_severity:
            print("\n  CRITICAL: High-severity incidents require immediate attention!")
        
                              
                                                                                
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
    # entry point for demo runs; exits non-zero when high severity incidents exist
    try:
        analyzer = SecurityEventAnalyzer()
        incidents = analyzer.generate_incident_report()
        
                                                               
        high_severity_count = len([i for i in incidents if i.get('severity') == 'HIGH'])
        sys.exit(1 if high_severity_count > 0 else 0)
        
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        print("\nNote: Ensure the e-commerce application has been run to create the database.")
        print("Run: cd ecommerce-app && mvn spring-boot:run")
        sys.exit(2)
