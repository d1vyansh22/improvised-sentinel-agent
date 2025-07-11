"""
Azure Sentinel Table Schema Definitions
This file contains the schema definitions for all Azure Sentinel tables used in the threat intelligence system.
"""

from typing import Dict, List, Any

# Azure Sentinel table schemas with field definitions and IoC mappings
AZURE_SENTINEL_TABLES = {
    "PassiveDNS": {
        "fields": {
            "ip": "string",
            "domain": "string"
        },
        "description": "DNS resolution data for passive DNS analysis",
        "primary_iocs": ["ip_address", "domain"],
        "common_filters": ["ip", "domain"],
        "sample_query": "PassiveDNS | where ip == '192.168.1.1' | limit 100"
    },

    "InboundBrowsing": {
        "fields": {
            "timestamp": "string",
            "timestamp_1": "datetime", 
            "method": "string",
            "src_ip": "string",
            "user_agent": "string",
            "url": "string"
        },
        "description": "Inbound web traffic and browsing activities",
        "primary_iocs": ["ip_address", "url", "user_agent"],
        "common_filters": ["src_ip", "url", "user_agent", "timestamp_1"],
        "sample_query": "InboundBrowsing | where src_ip == '10.0.0.1' | limit 100"
    },

    "ProcessEvents": {
        "fields": {
            "timestamp": "string",
            "timestamp_1": "datetime",
            "parent_process_name": "string", 
            "parent_process_hash": "string",
            "process_commandline": "string",
            "process_name": "string",
            "process_hash": "string",
            "hostname": "string"
        },
        "description": "System process execution events and process hierarchy",
        "primary_iocs": ["process_hash", "process_name", "hostname"],
        "common_filters": ["process_name", "process_hash", "hostname", "timestamp_1"],
        "sample_query": "ProcessEvents | where process_name contains 'powershell' | limit 100"
    },

    "Email": {
        "fields": {
            "sender": "string",
            "event_time": "string",
            "event_time_1": "datetime",
            "reply_to": "string", 
            "recipient": "string",
            "subject": "string",
            "accepted": "bool",
            "accepted_1": "string",
            "link": "guid",
            "link_1": "string"
        },
        "description": "Email communications and metadata",
        "primary_iocs": ["email_address", "domain", "url"],
        "common_filters": ["sender", "recipient", "subject", "event_time_1"],
        "sample_query": "Email | where sender contains 'suspicious' | limit 100"
    },

    "OutboundBrowsing": {
        "fields": {
            "timestamp": "string",
            "timestamp_1": "datetime",
            "method": "string",
            "src_ip": "string", 
            "user_agent": "string",
            "url": "string"
        },
        "description": "Outbound web traffic and external communications",
        "primary_iocs": ["ip_address", "url", "user_agent"],
        "common_filters": ["src_ip", "url", "user_agent", "timestamp_1"],
        "sample_query": "OutboundBrowsing | where url contains 'malicious' | limit 100"
    },

    "FileCreationEvents": {
        "fields": {
            "timestamp": "string",
            "timestamp_1": "datetime",
            "hostname": "string",
            "sha256": "string",
            "path": "string",
            "filename": "string",
            "size": "int",
            "size_1": "real"
        },
        "description": "File system events and file creation activities",
        "primary_iocs": ["file_hash", "filename", "hostname"],
        "common_filters": ["sha256", "filename", "path", "hostname", "timestamp_1"],
        "sample_query": "FileCreationEvents | where filename endswith '.exe' | limit 100"
    },

    "Employees": {
        "fields": {
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
        "description": "Employee information and user activity data",
        "primary_iocs": ["username", "email_address", "ip_address"],
        "common_filters": ["username", "email_addr", "ip_addr", "hostname", "timestamp"],
        "sample_query": "Employees | where role == 'admin' | limit 100"
    },

    "IAM": {
        "fields": {
            "Action": "string",
            "HostName": "string",
            "Source_IP": "string",
            "SourceIP_Location": "string",
            "TargetResource": "string",
            "Timestamp": "string",
            "UserName": "string",
            "UserAgent": "string"
        },
        "description": "Identity and Access Management events",
        "primary_iocs": ["username", "ip_address", "hostname"],
        "common_filters": ["UserName", "Source_IP", "Action", "Timestamp"],
        "sample_query": "IAM | where Action == 'Login' | limit 100"
    },

    "AuthenticationEvents": {
        "fields": {
            "hostname": "string",
            "password_hash": "guid",
            "result": "string",
            "src_ip": "string",
            "timestamp": "string",
            "timestamp_1": "datetime",
            "user_agent": "string",
            "username": "string"
        },
        "description": "Authentication attempts and login events",
        "primary_iocs": ["username", "ip_address", "hostname"],
        "common_filters": ["username", "src_ip", "result", "hostname", "timestamp_1"],
        "sample_query": "AuthenticationEvents | where result == 'Failed' | limit 100"
    }
}

# IoC type mapping for query enrichment
IOC_MAPPING = {
    "ip_address": ["PassiveDNS", "InboundBrowsing", "OutboundBrowsing", "Employees", "IAM", "AuthenticationEvents"],
    "domain": ["PassiveDNS", "Email"],
    "url": ["InboundBrowsing", "OutboundBrowsing", "Email"],
    "email_address": ["Email", "Employees"],
    "file_hash": ["ProcessEvents", "FileCreationEvents"],
    "process_name": ["ProcessEvents"],
    "hostname": ["ProcessEvents", "FileCreationEvents", "Employees", "IAM", "AuthenticationEvents"],
    "username": ["Employees", "IAM", "AuthenticationEvents"],
    "user_agent": ["InboundBrowsing", "OutboundBrowsing", "Employees", "AuthenticationEvents"]
}

# Common threat hunting patterns
THREAT_PATTERNS = {
    "lateral_movement": ["ProcessEvents", "AuthenticationEvents", "IAM"],
    "data_exfiltration": ["OutboundBrowsing", "FileCreationEvents", "Email"],
    "malware_execution": ["ProcessEvents", "FileCreationEvents"],
    "phishing": ["Email", "InboundBrowsing"],
    "brute_force": ["AuthenticationEvents", "IAM"],
    "dns_tunneling": ["PassiveDNS", "OutboundBrowsing"],
    "privilege_escalation": ["IAM", "ProcessEvents", "AuthenticationEvents"]
}

def get_table_schema(table_name: str) -> Dict[str, Any]:
    """Get schema information for a specific table."""
    return AZURE_SENTINEL_TABLES.get(table_name, {})

def get_tables_by_ioc(ioc_type: str) -> List[str]:
    """Get tables that contain a specific IoC type."""
    return IOC_MAPPING.get(ioc_type, [])

def get_all_table_names() -> List[str]:
    """Get all available table names."""
    return list(AZURE_SENTINEL_TABLES.keys())

def get_threat_hunting_tables(threat_type: str) -> List[str]:
    """Get recommended tables for specific threat hunting scenarios."""
    return THREAT_PATTERNS.get(threat_type, [])
