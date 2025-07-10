"""
KQL Generator Tool
Generates KQL queries from enriched threat hunting requests
"""

from langchain_core.tools import tool
from typing import Dict, List, Any
import sys
import os

# Add parent directory to path to import schemas
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from schemas.azure_schemas import AZURE_SENTINEL_SCHEMAS, get_table_schema

@tool
def generate_kql_queries(enriched_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates KQL queries from enriched threat hunting data.

    Args:
        enriched_data: Output from the query enricher tool

    Returns:
        Dictionary containing generated KQL queries for each selected table
    """

    selected_tables = enriched_data.get("selected_tables", [])
    ioc_types = enriched_data.get("ioc_types", [])
    time_range = enriched_data.get("time_range", "7d")
    original_query = enriched_data.get("original_query", "")

    queries = []

    for table in selected_tables:
        schema = get_table_schema(table)
        if not schema:
            continue

        # Generate basic KQL query structure
        kql_query = generate_table_query(table, schema, ioc_types, time_range, original_query)

        queries.append({
            "table": table,
            "query": kql_query,
            "confidence": calculate_query_confidence(table, ioc_types, original_query),
            "description": schema.get("description", ""),
            "expected_fields": schema.get("fields", [])
        })

    return {
        "queries": queries,
        "total_tables": len(selected_tables),
        "generation_metadata": {
            "time_range": time_range,
            "ioc_focus": ioc_types,
            "query_approach": "Multi-table threat hunting analysis"
        }
    }

def generate_table_query(table_name: str, schema: Dict, ioc_types: List[str], 
                        time_range: str, original_query: str) -> str:
    """Generate KQL query for a specific table"""

    fields = schema.get("fields", [])
    table_iocs = schema.get("ioc_types", [])

    # Base query structure
    query_parts = [f"{table_name}"]

    # Add time filter if timestamp field exists
    if "timestamp" in fields:
        query_parts.append(f"| where timestamp > ago({time_range})")
    elif "timestamp_1" in fields:
        query_parts.append(f"| where timestamp_1 > ago({time_range})")
    elif "TimeGenerated" in fields:
        query_parts.append(f"| where TimeGenerated > ago({time_range})")

    # Add specific filters based on query context and IOC types
    filters = generate_contextual_filters(table_name, ioc_types, original_query, fields)
    query_parts.extend(filters)

    # Add aggregation and limiting
    if "email" in original_query.lower() and table_name == "Email":
        query_parts.append("| summarize count() by sender, recipient")
        query_parts.append("| where count_ > 1")
    elif "login" in original_query.lower() and table_name == "AuthenticationEvents":
        query_parts.append("| summarize failed_attempts=countif(result != 'Success') by username, src_ip")
        query_parts.append("| where failed_attempts > 3")
    elif "process" in original_query.lower() and table_name == "ProcessEvents":
        query_parts.append("| summarize count() by process_name, hostname")
    else:
        # Default aggregation
        if len(fields) > 2:
            key_field = fields[0] if fields[0] != "timestamp" else fields[1]
            query_parts.append(f"| summarize count() by {key_field}")

    query_parts.append("| limit 100")

    return "\n".join(query_parts)

def generate_contextual_filters(table_name: str, ioc_types: List[str], 
                               original_query: str, fields: List[str]) -> List[str]:
    """Generate contextual filters based on query content"""
    filters = []
    query_lower = original_query.lower()

    # Suspicious activity patterns
    if "suspicious" in query_lower or "malicious" in query_lower:
        if table_name == "ProcessEvents" and "process_name" in fields:
            filters.append("| where process_name has_any('powershell', 'cmd', 'wscript', 'cscript')")
        elif table_name == "InboundBrowsing" or table_name == "OutBoundBrowsing":
            if "user_agent" in fields:
                filters.append("| where user_agent contains 'python' or user_agent contains 'curl'")

    # Failed/error patterns  
    if "failed" in query_lower or "error" in query_lower:
        if table_name == "AuthenticationEvents" and "result" in fields:
            filters.append("| where result != 'Success'")

    # External/unknown patterns
    if "external" in query_lower or "unknown" in query_lower:
        if "src_ip" in fields:
            filters.append("| where not(ipv4_is_private(src_ip))")
        elif "Source_IP" in fields:
            filters.append("| where not(ipv4_is_private(Source_IP))")

    # High volume patterns
    if "multiple" in query_lower or "many" in query_lower:
        # Will be handled in aggregation phase
        pass

    return filters

def calculate_query_confidence(table_name: str, ioc_types: List[str], original_query: str) -> float:
    """Calculate confidence score for generated query"""
    base_confidence = 0.7

    # Get table's IOC types
    schema = get_table_schema(table_name)
    table_iocs = schema.get("ioc_types", [])

    # Boost confidence if IOC types match
    ioc_match_score = len(set(ioc_types) & set(table_iocs)) / max(len(ioc_types), 1)

    # Boost confidence for direct keyword matches
    keyword_boost = 0.0
    query_lower = original_query.lower()
    if table_name.lower() in query_lower:
        keyword_boost = 0.1

    confidence = min(base_confidence + (ioc_match_score * 0.2) + keyword_boost, 0.95)
    return round(confidence, 2)

# Example usage function for testing
def test_kql_generator():
    """Test the KQL generator with sample enriched data"""
    test_enriched = {
        "original_query": "Find suspicious email activities from external domains",
        "selected_tables": ["Email", "PassiveDNS"],
        "ioc_types": ["email", "domain"],
        "time_range": "7d"
    }

    result = generate_kql_queries(test_enriched)

    print("Generated KQL Queries:")
    for query_info in result["queries"]:
        print(f"\nTable: {query_info['table']}")
        print(f"Confidence: {query_info['confidence']}")
        print(f"Query:\n{query_info['query']}")
        print("-" * 50)

if __name__ == "__main__":
    test_kql_generator()
