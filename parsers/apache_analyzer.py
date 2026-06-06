import re

pattern = re.compile(r'(\S+) - - \[(\d{2}\/\w{3}\/\d{4}):(\d{2}\:\d{2}\:\d{2}).*?"(.*?)"\s+(\d{3})')

def parse_apache(line):
    match = pattern.match(line)

    if match:
        return {
            "source" : "Apache",
            "ip" : match.group(1),
            "date" : match.group(2),
            "time" : match.group(3),
            "request" : match.group(4),
            "response_code" : match.group(5)
        }
    
    return None