"""
Sample queries for testing the threat intelligence system
"""

# Sample threat hunting queries organized by category
SAMPLE_QUERIES = {
    "email_security": [
        "Find suspicious email activities from external domains",
        "Detect phishing emails with malicious attachments",
        "Look for emails with suspicious sender reputation",
        "Find emails with cryptocurrency-related content",
        "Identify emails with embedded malicious URLs"
    ],

    "authentication": [
        "Look for failed login attempts from unusual IP addresses",
        "Find brute force authentication attempts",
        "Detect impossible travel authentication patterns",
        "Search for privileged account login anomalies",
        "Identify authentication bypass attempts"
    ],

    "malware_detection": [
        "Detect potential malware execution on endpoints",
        "Find suspicious process execution patterns",
        "Look for unauthorized file modifications",
        "Identify potential ransomware activities",
        "Search for living-off-the-land attack techniques"
    ],

    "network_security": [
        "Investigate DNS tunneling activities",
        "Find suspicious outbound network connections",
        "Detect potential data exfiltration attempts",
        "Look for command and control communication",
        "Identify unusual network traffic patterns"
    ],

    "privilege_escalation": [
        "Search for privilege escalation attempts",
        "Find unauthorized administrative access",
        "Detect lateral movement activities",
        "Look for suspicious service account usage",
        "Identify potential insider threat activities"
    ],

    "data_access": [
        "Find unauthorized file access patterns",
        "Detect sensitive data access anomalies",
        "Look for bulk data download activities",
        "Identify unauthorized database access",
        "Search for data classification violations"
    ]
}

# Complex multi-table queries
COMPLEX_QUERIES = [
    "Find users who received suspicious emails and then accessed sensitive files",
    "Detect authentication failures followed by successful logins from different locations",
    "Look for processes that were started after suspicious email interactions",
    "Find DNS queries that correlate with suspicious file downloads",
    "Identify user accounts that show both authentication anomalies and data access patterns"
]

# Time-based queries
TIME_BASED_QUERIES = [
    "Find security events that occurred during off-hours last week",
    "Look for unusual activities during the last 24 hours",
    "Detect patterns that occurred over the past month",
    "Find activities that happened during maintenance windows",
    "Look for events that occurred during specific time ranges"
]

# IoC-specific queries
IOC_QUERIES = [
    "Find all activities related to IP address 192.168.1.100",
    "Look for activities involving the domain suspicious-site.com",
    "Search for all instances of file hash abc123def456",
    "Find activities related to user account john.doe@company.com",
    "Look for all activities involving the hostname DESKTOP-MALWARE"
]

def get_all_sample_queries():
    """Get all sample queries as a flat list"""
    all_queries = []
    for category, queries in SAMPLE_QUERIES.items():
        all_queries.extend(queries)
    all_queries.extend(COMPLEX_QUERIES)
    all_queries.extend(TIME_BASED_QUERIES)
    all_queries.extend(IOC_QUERIES)
    return all_queries

def get_queries_by_category(category):
    """Get queries for a specific category"""
    return SAMPLE_QUERIES.get(category, [])

def get_random_query():
    """Get a random sample query"""
    import random
    all_queries = get_all_sample_queries()
    return random.choice(all_queries)

if __name__ == "__main__":
    print("Sample Threat Intelligence Queries")
    print("=" * 40)

    for category, queries in SAMPLE_QUERIES.items():
        print(f"\n{category.upper()}:")
        for i, query in enumerate(queries, 1):
            print(f"  {i}. {query}")

    print(f"\nCOMPLEX QUERIES:")
    for i, query in enumerate(COMPLEX_QUERIES, 1):
        print(f"  {i}. {query}")

    print(f"\nTotal sample queries: {len(get_all_sample_queries())}")
