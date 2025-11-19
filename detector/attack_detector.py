import re
from typing import Dict, List, Set

class AttackDetector:
    def __init__(self):
        self.attack_patterns = {
            'SQL Injection': [
                r"(\bUNION\b.*\bSELECT\b)",
                r"(\bOR\b\s+[\d'\"]+\s*=\s*[\d'\"]+)",
                r"(--\s*$|#\s*$|\/\*.*\*\/)",
                r"(\bDROP\b\s+\bTABLE\b)",
                r"(\bINSERT\b\s+\bINTO\b)",
                r"(\bDELETE\b\s+\bFROM\b)",
                r"(\bUPDATE\b\s+.*\bSET\b)",
                r"(';|\";\s*--)",
                r"(\bEXEC\b\s*\(|\bEXECUTE\b)",
                r"(@@version|user\(\)|database\(\))",
                r"(information_schema|mysql\.user)",
                r"(\bAND\b\s+[\d'\"]+\s*=\s*[\d'\"]+)"
            ],
            'XSS': [
                r"(<script[^>]*>.*?</script>)",
                r"(<script[^>]*>)",
                r"(javascript:)",
                r"(onerror\s*=)",
                r"(onload\s*=)",
                r"(onclick\s*=)",
                r"(onmouseover\s*=)",
                r"(<iframe[^>]*>)",
                r"(<img[^>]*onerror)",
                r"(<svg[^>]*onload)",
                r"(alert\s*\()",
                r"(eval\s*\()",
                r"(document\.cookie)",
                r"(String\.fromCharCode)"
            ],
            'Directory Traversal': [
                r"(\.\./|\.\.\\)",
                r"(%2e%2e/|%2e%2e\\|%2e%2e%2f)",
                r"(\.\.;/|\.\.;\\)",
                r"(/etc/passwd|/etc/shadow)",
                r"(c:\\windows\\|c:/windows/)",
                r"(\.\.%5c|\.\.%2f)",
                r"(/\.\.%00|\\\.\.%00)"
            ],
            'Command Injection': [
                r"(;\s*ls\b|;\s*dir\b)",
                r"(\|\s*cat\b|\|\s*type\b)",
                r"(;\s*wget\b|;\s*curl\b)",
                r"(`.*`)",
                r"(\$\(.*\))",
                r"(;\s*rm\b|;\s*del\b)",
                r"(;\s*nc\b|;\s*netcat\b)",
                r"(&&\s*\w+|&\s*\w+)",
                r"(\|\|\s*\w+)",
                r"(;\s*chmod\b|;\s*chown\b)",
                r"(/bin/bash|/bin/sh|cmd\.exe)"
            ],
            'File Inclusion': [
                r"(php://filter|php://input)",
                r"(file://|expect://)",
                r"(data://text/plain)",
                r"(\?page=.*\.\./)",
                r"(\?file=.*\.\./)",
                r"(\?include=.*\.\./)",
                r"(\?path=.*\.\./)",
                r"(\.php\?.*=http://)",
                r"(\.php\?.*=ftp://)"
            ]
        }
        
        self.compiled_patterns = {}
        for attack_type, patterns in self.attack_patterns.items():
            self.compiled_patterns[attack_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]

    def detect_attacks(self, log_entry: Dict[str, str]) -> List[Dict[str, any]]:
        detected_attacks = []
        url = log_entry.get('url', '')
        
        for attack_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(url)
                if match:
                    detected_attacks.append({
                        'attack_type': attack_type,
                        'matched_pattern': pattern.pattern,
                        'matched_payload': match.group(0),
                        'full_url': url,
                        'ip': log_entry.get('ip', ''),
                        'timestamp': log_entry.get('timestamp', ''),
                        'method': log_entry.get('method', ''),
                        'user_agent': log_entry.get('user_agent', ''),
                        'status': log_entry.get('status', ''),
                        'line_number': log_entry.get('line_number', 0)
                    })
                    break
        
        return detected_attacks

    def analyze_logs(self, parsed_logs: List[Dict[str, str]]) -> Dict[str, any]:
        all_attacks = []
        attack_type_counts = {}
        ip_attacks = {}
        
        for log_entry in parsed_logs:
            attacks = self.detect_attacks(log_entry)
            if attacks:
                all_attacks.extend(attacks)
                
                for attack in attacks:
                    attack_type = attack['attack_type']
                    attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
                    
                    ip = attack['ip']
                    if ip not in ip_attacks:
                        ip_attacks[ip] = []
                    ip_attacks[ip].append(attack_type)
        
        return {
            'total_attacks': len(all_attacks),
            'attacks': all_attacks,
            'attack_type_counts': attack_type_counts,
            'ip_attacks': ip_attacks,
            'unique_ips': len(ip_attacks)
        }
