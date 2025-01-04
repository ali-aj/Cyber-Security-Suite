import re
from collections import defaultdict
from datetime import datetime

def analyze(log_data):
    patterns = {
        'sql_injection': {
            'pattern': r"(?:--|;|/\*|\*/|#|'|\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE|ALTER|CREATE|TRUNCATE|REPLACE|MERGE)\b|OR\s+1=1|AND\s+1=1)",
            'severity': 'high',
            'message': 'SQL Injection attempt detected',
            'remediation': 'Implement input validation and prepared statements'
        },
        'xss': {
            'pattern': r"<script.*?>.*?</script>|javascript:|on\w+\s*=|\b(alert|eval|setTimeout|setInterval)\b",
            'severity': 'high',
            'message': 'Cross-site scripting attempt detected',
            'remediation': 'Implement output encoding and CSP headers'
        },
        'path_traversal': {
            'pattern': r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|C:\\\\windows\\\\system32)",
            'severity': 'high',
            'message': 'Directory traversal attempt detected',
            'remediation': 'Validate file paths and implement proper access controls'
        },
        'auth_failure': {
            'pattern': r"failed login|invalid password|authentication failed",
            'severity': 'medium',
            'message': 'Multiple authentication failures detected',
            'remediation': 'Implement account lockout policies'
        },
        'port_scan': {
            'pattern': r"port scan|multiple ports|sequential connection",
            'severity': 'medium',
            'message': 'Potential port scanning activity detected',
            'remediation': 'Configure firewall rules and IPS'
        },
        'ddos': {
            'pattern': r"excessive requests|rate limit exceeded|dos attack",
            'severity': 'high',
            'message': 'Potential DDoS attack detected',
            'remediation': 'Implement rate limiting and DDoS protection'
        }
    }

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    timestamp_pattern = r'\[(.*?)\]'

    results = {
        'findings': {},
        'overall_severity': 'low',
        'ips': defaultdict(int),
        'timestamps': [],
        'remediation': []
    }
    
    severity_scores = {'high': 0, 'medium': 0, 'low': 0}

    # Extract IPs and timestamps
    ips = re.findall(ip_pattern, log_data)
    timestamps = re.findall(timestamp_pattern, log_data)
    
    for ip in ips:
        results['ips'][ip] += 1
    
    for timestamp in timestamps:
        try:
            dt = datetime.strptime(timestamp.strip(), '%Y-%m-%d %H:%M:%S')
            results['timestamps'].append(dt.isoformat())
        except ValueError:
            continue

    for attack_type, config in patterns.items():
        matches = list(re.finditer(config['pattern'], log_data, re.IGNORECASE))
        match_count = len(matches)
        
        if match_count > 0:
            severity_scores[config['severity']] += 1
            results['findings'][attack_type] = {
                'detected': True,
                'count': match_count,
                'severity': config['severity'],
                'message': config['message'],
                'remediation': config['remediation']
            }
            results['remediation'].append(config['remediation'])
        else:
            results['findings'][attack_type] = {
                'detected': False,
                'count': 0,
                'severity': 'low',
                'message': 'No suspicious activity detected'
            }

    # Calculate overall severity
    if severity_scores['high'] > 0:
        results['overall_severity'] = 'high'
    elif severity_scores['medium'] > 0:
        results['overall_severity'] = 'medium'
    
    return results