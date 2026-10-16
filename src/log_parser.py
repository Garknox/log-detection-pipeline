import re
from typing import Dict, Optional

class LogParser:
    """
    Parses raw web server access logs (Common / Combined Log Format) 
    into structured dictionary fields using Regular Expressions.
    """
    
    # Standard Apache/Nginx Combined Log Format RegEx Pattern
    LOG_PATTERN = re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'  # Client IP
        r'(?P<ident>\S+)\s+'                    # Remote logname (usually '-')
        r'(?P<user>\S+)\s+'                     # Remote user (usually '-')
        r'\[(?P<timestamp>[^\]]+)\]\s+'         # Timestamp
        r'"(?P<method>[A-Z]+)\s+'               # HTTP Method (GET, POST, etc.)
        r'(?P<url>[^\s]+)\s+'                   # Request URI / Endpoint
        r'HTTP/(?P<http_version>[\d\.]+)"\s+'   # HTTP Protocol Version
        r'(?P<status>\d{3})\s+'                 # HTTP Status Code
        r'(?P<bytes_sent>\S+)\s+'               # Bytes sent
        r'"(?P<referrer>[^"]*)"\s+'             # Referrer header
        r'"(?P<user_agent>[^"]*)"'              # User-Agent header
    )

    def parse_line(self, log_line: str) -> Optional[Dict[str, str]]:
        """
        Parses a single line of log text and returns a structured dictionary,
        or None if the line does not match the expected pattern.
        """
        match = self.LOG_PATTERN.match(log_line.strip())
        if not match:
            return None
        
        return match.groupdict()

if __name__ == "__main__":
    # Quick local test of the parser
    parser = LogParser()
    sample_log = '192.168.1.50 - - [16/Oct/2026:12:00:00 -0500] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
    
    parsed = parser.parse_line(sample_log)
    print("Parsed Log Output:")
    for key, value in parsed.items():
        print(f"  {key}: {value}")
