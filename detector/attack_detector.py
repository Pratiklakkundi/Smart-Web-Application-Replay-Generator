import re
from typing import Dict, List, Set, Optional

class AttackDetector:
    def __init__(self, db_manager=None, enable_learning=False):
        self.db_manager = db_manager
        self.enable_learning = enable_learning
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
        
        if self.db_manager:
            self.load_custom_patterns()
    
    def load_custom_patterns(self):
        if not self.db_manager:
            return
        
        try:
            custom_patterns = self.db_manager.get_custom_patterns(active_only=True)
            for pattern_data in custom_patterns:
                attack_type = pattern_data['attack_type']
                pattern_regex = pattern_data['pattern_regex']
                
                if attack_type not in self.compiled_patterns:
                    self.compiled_patterns[attack_type] = []
                
                try:
                    compiled = re.compile(pattern_regex, re.IGNORECASE)
                    self.compiled_patterns[attack_type].append(compiled)
                except re.error:
                    pass
        except Exception:
            pass

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
        unknown_count = 0
        
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
            elif self.enable_learning and self.db_manager:
                status_code = log_entry.get('status', '')
                if status_code and status_code not in ['200', '201', '204', '301', '302', '304']:
                    try:
                        self.db_manager.track_unknown_attack(
                            url=log_entry.get('url', ''),
                            ip=log_entry.get('ip', ''),
                            timestamp=log_entry.get('timestamp', ''),
                            method=log_entry.get('method', ''),
                            user_agent=log_entry.get('user_agent', '')
                        )
                        unknown_count += 1
                    except Exception:
                        pass
        
        return {
            'total_attacks': len(all_attacks),
            'attacks': all_attacks,
            'attack_type_counts': attack_type_counts,
            'ip_attacks': ip_attacks,
            'unique_ips': len(ip_attacks),
            'unknown_tracked': unknown_count
        }
