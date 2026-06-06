import re

def parse_date(line):
    pattern = r'(\w+\s+\d+)'
    match = re.match(pattern, line)

    if match:
        return match.group(1)
    
    return None

def parse_time(line):
    pattern = r'(\d{2}:\d{2}:\d{2})'
    match = re.search(pattern, line)

    if match:
        return match.group(1)
    
    return None

def parse_event_type(line):
    pattern = r'(Failed password|authentication failure|Connection closed|Received disconnect|Disconnected from authenticating|Accepted password|Accepted publickey|Invalid user)'
    match = re.search(pattern, line)

    if match:
        return match.group(1)
    
    return None

def parse_ip(line):
    patterns = [
        r'user\s+\w+\s+([\d.]+)',
        r'rhost=([\d.]+)',
        r'from\s+([\d.]+)\s+port'
    ]

    for pattern in patterns:
        match = re.search(pattern, line)
    
        if match:
            return match.group(1)
    
    return None

def parse_port(line):
    pattern = r'port\s+(\d+)'
    match = re.search(pattern, line)

    if match:
        return match.group(1)
    
    return None

def parse_target_username(line):
    patterns = [
        r'user=(\w+)',
        r'USER=(\w+)',
        r'for\s+(?:invalid user\s+)?([\w.-]+)',
        r'user\s+(\w+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line)
        
        if match:
            return match.group(1)
    
    return None


def parse_linux_auth(line):
    return {
        "source" : "auth",
        "date" : parse_date(line),
        "time" : parse_time(line),
        "ip" : parse_ip(line),
        "port" : parse_port(line),
        "service" : "sshd",
        "event_type" : parse_event_type(line),
        "target_username" : parse_target_username(line),
    }