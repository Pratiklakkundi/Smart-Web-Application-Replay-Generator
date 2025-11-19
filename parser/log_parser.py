import re
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, unquote

class LogParser:
    def __init__(self):
        self.apache_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<url>[^\s]+) HTTP/[\d\.]+"\s+'
            r'(?P<status>\d+)\s+(?P<size>\d+|-)\s*'
            r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
        )
        
        self.nginx_pattern = re.compile(
            r'(?P<ip>[\d\.]+) - - \[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<url>[^\s]+) HTTP/[\d\.]+"\s+'
            r'(?P<status>\d+)\s+(?P<size>\d+)\s*'
            r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
        )

    def parse_log_file(self, log_content: str) -> List[Dict[str, str]]:
        parsed_logs = []
        lines = log_content.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            if not line.strip():
                continue
            
            parsed_entry = self._parse_line(line)
            if parsed_entry:
                parsed_entry['line_number'] = line_num
                parsed_logs.append(parsed_entry)
        
        return parsed_logs

    def _parse_line(self, line: str) -> Optional[Dict[str, str]]:
        match = self.apache_pattern.match(line) or self.nginx_pattern.match(line)
        
        if not match:
            return None
        
        data = match.groupdict()
        
        url = unquote(data.get('url', ''))
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        return {
            'ip': data.get('ip', ''),
            'timestamp': data.get('timestamp', ''),
            'method': data.get('method', ''),
            'url': url,
            'path': parsed_url.path,
            'query_string': parsed_url.query,
            'query_params': query_params,
            'status': data.get('status', ''),
            'size': data.get('size', ''),
            'referrer': data.get('referrer', ''),
            'user_agent': data.get('user_agent', ''),
            'raw_line': line
        }

    def get_payload_from_entry(self, entry: Dict[str, str]) -> str:
        url = entry.get('url', '')
        query_string = entry.get('query_string', '')
        
        if query_string:
            return f"{entry.get('path', '')}?{query_string}"
        return entry.get('path', '')
