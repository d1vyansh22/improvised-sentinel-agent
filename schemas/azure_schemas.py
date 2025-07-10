"""
Azure Sentinel Table Schemas
Simple schema definitions for the 9 security log tables
"""

from typing import Dict, List, Any

# Schema definitions for the 9 Azure Sentinel tables
AZURE_SENTINEL_SCHEMAS = {
    "PassiveDNS": {
        "fields": ["ip", "domain"],
        "types": {"ip": "string", "domain": "string"},
        "description": "DNS resolution analysis",
        "ioc_types": ["ip_address", "domain"]
    },
    "InboundBrowsing": {
        "fields": ["timestamp", "timestamp_1", "method", "src_ip", "user_agent", "url"],
        "types": {
            "timestamp": "string", 
            "timestamp_1": "datetime", 
            "method": "string",
            "src_ip": "string", 
            "user_agent": "string", 
            "url": "string"
        },
        "description": "Inbound web traffic analysis",
        "ioc_types": ["ip_address", "url", "user_agent"]
    },
    "ProcessEvents": {
        "fields": ["timestamp", "timestamp_1", "parent_process_name", "parent_process_hash", 
                  "process_commandline", "process_name", "process_hash", "hostname"],
        "types": {
            "timestamp": "string", 
            "timestamp_1": "datetime",
            "parent_process_name": "string",
            "parent_process_hash": "string",
            "process_commandline": "string", 
            "process_name": "string",
            "process_hash": "string", 
            "hostname": "string"
        },
        "description": "Process execution monitoring",
        "ioc_types": ["file_hash", "hostname", "process_name"]
    },
    "Email": {
        "fields": ["sender", "event_time", "event_time_1", "reply_to", "recipient", 
                  "subject", "accepted", "accepted_1", "link"],
        "types": {
            "sender": "string", 
            "event_time": "string", 
            "event_time_1": "datetime",
            "reply_to": "string", 
            "recipient": "string", 
            "subject": "string",
            "accepted": "bool", 
            "accepted_1": "string", 
            "link": "string"
        },
        "description": "Email communication analysis",
        "ioc_types": ["email", "domain", "url"]
    },
    "OutBoundBrowsing": {
        "fields": ["timestamp", "timestamp_1", "method", "src_ip", "user_agent", "url"],
        "types": {
            "timestamp": "string", 
            "timestamp_1": "datetime", 
            "method": "string",
            "src_ip": "string", 
            "user_agent": "string", 
            "url": "string"
        },
        "description": "Outbound web traffic analysis", 
        "ioc_types": ["ip_address", "url", "user_agent"]
    },
    "FileCreationEvents": {
        "fields": ["timestamp", "timestamp_1", "hostname", "sha256", "path", "filename", "size", "size_1"],
        "types": {
            "timestamp": "string", 
            "timestamp_1": "datetime", 
            "hostname": "string",
            "sha256": "string", 
            "path": "string", 
            "filename": "string",
            "size": "int", 
            "size_1": "real"
        },
        "description": "File creation monitoring",
        "ioc_types": ["file_hash", "hostname", "filename"]
    },
    "Employees": {
        "fields": ["name", "timestamp", "user_agent", "ip_addr", "email_addr", 
                  "company_domain", "username", "role", "hostname"],
        "types": {
            "name": "string", 
            "timestamp": "datetime", 
            "user_agent": "string",
            "ip_addr": "string", 
            "email_addr": "string", 
            "company_domain": "string",
            "username": "string", 
            "role": "string", 
            "hostname": "string"
        },
        "description": "Employee activity tracking",
        "ioc_types": ["ip_address", "email", "hostname"]
    },
    "IAM": {
        "fields": ["Action", "HostName", "Source_IP", "SourceIP_Location", 
                  "TargetResource", "Timestamp", "UserName", "UserAgent"],
        "types": {
            "Action": "string", 
            "HostName": "string", 
            "Source_IP": "string",
            "SourceIP_Location": "string", 
            "TargetResource": "string", 
            "Timestamp": "string",
            "UserName": "string", 
            "UserAgent": "string"
        },
        "description": "Identity and access management",
        "ioc_types": ["ip_address", "hostname", "username"]
    },
    "AuthenticationEvents": {
        "fields": ["hostname", "password_hash", "result", "src_ip", "timestamp", 
                  "timestamp_1", "user_agent", "username"],
        "types": {
            "hostname": "string", 
            "password_hash": "guid", 
            "result": "string",
            "src_ip": "string", 
            "timestamp": "string", 
            "timestamp_1": "datetime",
            "user_agent": "string", 
            "username": "string"
        },
        "description": "Authentication event monitoring",
        "ioc_types": ["ip_address", "hostname", "username"]
    }
}

def get_table_schema(table_name: str) -> Dict[str, Any]:
    """Get schema for a specific table"""
    return AZURE_SENTINEL_SCHEMAS.get(table_name, {})

def get_relevant_tables(ioc_types: List[str], max_tables: int = 4) -> List[str]:
    """Get most relevant tables based on IOC types"""
    table_scores = {}

    for table_name, schema in AZURE_SENTINEL_SCHEMAS.items():
        score = 0
        for ioc_type in ioc_types:
            if ioc_type in schema.get("ioc_types", []):
                score += 1
        table_scores[table_name] = score

    # Sort by score and return top tables
    sorted_tables = sorted(table_scores.items(), key=lambda x: x[1], reverse=True)
    return [table[0] for table in sorted_tables[:max_tables] if table[1] > 0]

def identify_ioc_types(query: str) -> List[str]:
    """Simple IOC type identification from query"""
    query_lower = query.lower()
    ioc_types = []

    ioc_keywords = {
        "ip_address": ["ip", "address", "source ip", "src_ip", "network"],
        "domain": ["domain", "dns", "website", "site"],
        "email": ["email", "mail", "sender", "recipient"],
        "file_hash": ["hash", "md5", "sha256", "file", "malware"],
        "url": ["url", "link", "web", "http", "https"],
        "hostname": ["host", "machine", "computer", "server"],
        "username": ["user", "account", "login", "authentication"],
        "process_name": ["process", "executable", "program"],
        "user_agent": ["browser", "agent", "client"]
    }

    for ioc_type, keywords in ioc_keywords.items():
        if any(keyword in query_lower for keyword in keywords):
            ioc_types.append(ioc_type)

    return ioc_types if ioc_types else ["ip_address", "domain"]  # Default
