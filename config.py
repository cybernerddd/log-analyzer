# contains suspicious agents list, will be scaled
suspicious_agents = [
"curl",
"python-requests",
"sqlmap",
"Burp",
"Gobuster",
"ffuf",
"dirbuster",
"nikto",
"nmap",
"masscan",
"wpscan"
]

# common status codes
status_codes = [
"200",
"201",
"301",
"302",
"400",
"401",
"403",
"404",
"500",
"502",
"503"
]

# HTTP methods list
http_methods = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "OPTIONS",
    "HEAD"
]

# Common SQL Injection (SQLi) detection signatures and keywords
sqli_indicators = [
    # Boolean-based patterns
    "or 1=1",
    "or '1'='1",
    "or true",
    "and 1=1",
    "and '1'='1",
    
    # SQL syntax and comment characters
    "--",
    "#",
    "/*",
    "*/",
    ";",
    
    # Signatures for unauthorized data retrieval
    "union select",
    "union all select",
    "select * from",
    
    # Metadata and system signatures
    "sqlite_version",
    "version()",
    "@@version",
    "table_name",
    "column_name",
    "information_schema",
    
    # Signatures for time-based analysis
    "sleep(",
    "benchmark(",
    "pg_sleep",
    "waitfor delay",
    
    # Data definition and execution keywords
    "drop table",
    "insert into",
    "update set",
    "exec("
]
