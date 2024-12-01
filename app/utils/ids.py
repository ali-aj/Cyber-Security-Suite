import re

def analyze(log_data):
    patterns = {
        # SQL Injection patterns
        'sql_injection': r"(?:--|;|/\*|\*/|#|'|\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|EXECUTE|ALTER|CREATE|TRUNCATE|REPLACE|MERGE)\b|OR\s+1=1|AND\s+1=1)",

        # XSS patterns
        'xss': r"<script.*?>.*?</script>|javascript:|on\w+\s*=",

        # Path Traversal patterns
        'path_traversal': r"(?:\.\./|\.\.\\|/etc/passwd|/etc/shadow|C:\\\\windows\\\\system32)"
    }

    results = {}
    for attack_type, pattern in patterns.items():
        if re.search(pattern, log_data, re.IGNORECASE):
            results[attack_type] = "Potential attack detected"
        else:
            results[attack_type] = "No suspicious activity"

    return results



