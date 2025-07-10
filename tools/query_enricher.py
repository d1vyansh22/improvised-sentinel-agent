"""
Query Enricher Tool
Enriches user queries and selects relevant Azure Sentinel tables
"""

from langchain_core.tools import tool
from typing import Dict, List, Any
import sys
import os

# Add parent directory to path to import schemas
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from schemas.azure_schemas import AZURE_SENTINEL_SCHEMAS, get_relevant_tables, identify_ioc_types

@tool
def enrich_user_query(user_query: str) -> Dict[str, Any]:
    """
    Enriches a natural language threat hunting query and selects relevant Azure Sentinel tables.

    Args:
        user_query: Natural language threat hunting request from user

    Returns:
        Dictionary containing enriched query, selected tables, and IOC types
    """

    # Identify IOC types from the query
    ioc_types = identify_ioc_types(user_query)

    # Get relevant tables (max 4)
    relevant_tables = get_relevant_tables(ioc_types, max_tables=4)

    # Create enriched query with more specific threat hunting context
    enriched_query = f"""
    Threat hunting request: {user_query}

    Focus areas:
    - IOC types to investigate: {', '.join(ioc_types)}
    - Security context: Look for suspicious patterns, anomalies, and potential threats
    - Time-based analysis: Consider recent activities and timeline correlations
    """

    # Add time range suggestion based on query
    time_range = "7d"  # Default to last 7 days
    if "today" in user_query.lower():
        time_range = "1d"
    elif "week" in user_query.lower():
        time_range = "7d"
    elif "month" in user_query.lower():
        time_range = "30d"

    result = {
        "original_query": user_query,
        "enriched_query": enriched_query.strip(),
        "selected_tables": relevant_tables,
        "ioc_types": ioc_types,
        "time_range": time_range,
        "confidence_score": 0.85,  # Simple confidence score
        "analysis_context": {
            "threat_focus": "Investigate potential security threats and anomalies",
            "recommended_approach": "Multi-table correlation analysis",
            "priority_fields": [schema["ioc_types"] for schema in 
                              [AZURE_SENTINEL_SCHEMAS[table] for table in relevant_tables]]
        }
    }

    return result

# Example usage function for testing
def test_enricher():
    """Test the enricher with sample queries"""
    test_queries = [
        "Find suspicious email activities from external domains",
        "Detect failed login attempts from unknown IP addresses", 
        "Identify potential malware file executions",
        "Look for unusual DNS queries to suspicious domains"
    ]

    for query in test_queries:
        result = enrich_user_query(query)
        print(f"Query: {query}")
        print(f"Tables: {result['selected_tables']}")
        print(f"IOCs: {result['ioc_types']}")
        print("-" * 50)

if __name__ == "__main__":
    test_enricher()
