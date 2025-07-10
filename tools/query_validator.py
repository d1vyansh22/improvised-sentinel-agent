"""
Query Validator Tool
Validates and refines KQL queries with basic syntax and semantic checks
"""

from langchain_core.tools import tool
from typing import Dict, List, Any
import re
import sys
import os

# Add parent directory to path to import schemas
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from schemas.azure_schemas import AZURE_SENTINEL_SCHEMAS, get_table_schema

@tool
def validate_and_refine_queries(query_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates KQL queries and provides basic refinements and error checking.

    Args:
        query_data: Output from the KQL generator tool

    Returns:
        Dictionary containing validated queries with error analysis and suggestions
    """

    queries = query_data.get("queries", [])
    validated_queries = []

    for query_info in queries:
        table = query_info.get("table", "")
        kql_query = query_info.get("query", "")

        # Perform validation
        validation_result = validate_single_query(kql_query, table)

        # Create enhanced query info with validation results
        validated_query = {
            **query_info,
            "original_query": kql_query,
            "validation_passed": validation_result["is_valid"],
            "validation_errors": validation_result["errors"],
            "validation_warnings": validation_result["warnings"],
            "refined_query": validation_result.get("refined_query", kql_query),
            "validation_score": validation_result["score"],
            "suggestions": validation_result["suggestions"]
        }

        validated_queries.append(validated_query)

    # Calculate overall validation metrics
    total_queries = len(validated_queries)
    passed_queries = sum(1 for q in validated_queries if q["validation_passed"])
    success_rate = (passed_queries / total_queries) if total_queries > 0 else 0

    return {
        "validated_queries": validated_queries,
        "validation_summary": {
            "total_queries": total_queries,
            "passed_validation": passed_queries,
            "success_rate": round(success_rate, 2),
            "avg_validation_score": round(
                sum(q["validation_score"] for q in validated_queries) / total_queries, 2
            ) if total_queries > 0 else 0
        },
        "overall_status": "PASSED" if success_rate >= 0.8 else "NEEDS_REVIEW"
    }

def validate_single_query(kql_query: str, table_name: str) -> Dict[str, Any]:
    """Validate a single KQL query"""

    errors = []
    warnings = []
    suggestions = []
    score = 1.0

    # Get table schema for validation
    schema = get_table_schema(table_name)
    valid_fields = schema.get("fields", [])

    # Basic syntax validation
    syntax_check = validate_syntax(kql_query)
    if not syntax_check["is_valid"]:
        errors.extend(syntax_check["errors"])
        score -= 0.3

    # Field validation
    field_check = validate_fields(kql_query, valid_fields, table_name)
    if field_check["invalid_fields"]:
        warnings.extend([f"Unknown field: {field}" for field in field_check["invalid_fields"]])
        score -= 0.1 * len(field_check["invalid_fields"])

    # Performance validation
    performance_check = validate_performance(kql_query)
    if performance_check["warnings"]:
        warnings.extend(performance_check["warnings"])
        suggestions.extend(performance_check["suggestions"])

    # Logical validation
    logic_check = validate_logic(kql_query, table_name)
    suggestions.extend(logic_check["suggestions"])

    # Generate refined query if needed
    refined_query = refine_query(kql_query, table_name, valid_fields) if errors or warnings else kql_query

    is_valid = len(errors) == 0
    final_score = max(0.0, min(1.0, score))

    return {
        "is_valid": is_valid,
        "errors": errors,
        "warnings": warnings,
        "suggestions": suggestions,
        "score": round(final_score, 2),
        "refined_query": refined_query
    }

def validate_syntax(kql_query: str) -> Dict[str, Any]:
    """Basic KQL syntax validation"""
    errors = []

    # Check for basic KQL structure
    if not kql_query.strip():
        errors.append("Query is empty")
        return {"is_valid": False, "errors": errors}

    lines = [line.strip() for line in kql_query.split('\n') if line.strip()]

    # First line should be table name (basic check)
    if not lines:
        errors.append("No query content found")
        return {"is_valid": False, "errors": errors}

    first_line = lines[0]
    if '|' in first_line and not first_line.startswith('|'):
        errors.append("First line should be table name without pipe operator")

    # Check for unmatched parentheses
    open_parens = kql_query.count('(')
    close_parens = kql_query.count(')')
    if open_parens != close_parens:
        errors.append(f"Unmatched parentheses: {open_parens} open, {close_parens} close")

    # Check for proper pipe usage
    for i, line in enumerate(lines[1:], 1):  # Skip first line
        if line and not line.startswith('|'):
            errors.append(f"Line {i+1} should start with pipe operator (|)")

    # Check for dangerous operators (basic security)
    dangerous_ops = ['drop', 'delete', 'create', 'alter']
    for op in dangerous_ops:
        if re.search(rf'\b{op}\b', kql_query, re.IGNORECASE):
            errors.append(f"Potentially dangerous operation detected: {op}")

    return {"is_valid": len(errors) == 0, "errors": errors}

def validate_fields(kql_query: str, valid_fields: List[str], table_name: str) -> Dict[str, Any]:
    """Validate field names used in the query"""

    # Extract field names from query (basic regex)
    field_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:[><=!]|has|contains|startswith|endswith)'
    found_fields = re.findall(field_pattern, kql_query, re.IGNORECASE)

    # Also check fields in summarize, project, etc.
    summarize_pattern = r'summarize[^|]*by\s+([^|\n]+)'
    project_pattern = r'project\s+([^|\n]+)'

    for pattern in [summarize_pattern, project_pattern]:
        matches = re.findall(pattern, kql_query, re.IGNORECASE)
        for match in matches:
            # Split by comma and clean up
            fields_in_clause = [f.strip() for f in match.split(',')]
            found_fields.extend(fields_in_clause)

    # Remove duplicates and filter out obvious non-field names
    found_fields = list(set([f for f in found_fields if f and not f.isdigit() and len(f) > 1]))

    # Check against valid fields
    invalid_fields = [f for f in found_fields if f not in valid_fields and f not in 
                     ['count_', 'count', 'avg', 'sum', 'max', 'min']]  # Common aggregation fields

    return {
        "found_fields": found_fields,
        "invalid_fields": invalid_fields
    }

def validate_performance(kql_query: str) -> Dict[str, Any]:
    """Check for potential performance issues"""
    warnings = []
    suggestions = []

    # Check for missing time filters
    if not re.search(r'ago\s*\(', kql_query, re.IGNORECASE):
        warnings.append("No time filter detected - query may be slow on large datasets")
        suggestions.append("Add a time filter like: | where timestamp > ago(7d)")

    # Check for missing limits
    if not re.search(r'\|\s*limit\s+\d+', kql_query, re.IGNORECASE):
        suggestions.append("Consider adding a limit clause to control result size")

    # Check for potentially expensive operations
    if re.search(r'contains|has_any|startswith|endswith', kql_query, re.IGNORECASE):
        suggestions.append("String operations detected - ensure proper indexing for performance")

    return {"warnings": warnings, "suggestions": suggestions}

def validate_logic(kql_query: str, table_name: str) -> Dict[str, Any]:
    """Validate logical consistency of the query"""
    suggestions = []

    # Check for meaningful aggregations
    if 'summarize' in kql_query.lower():
        if 'count()' not in kql_query.lower():
            suggestions.append("Consider using count() in summarize for threat hunting analysis")

    # Table-specific suggestions
    if table_name == "AuthenticationEvents":
        if 'result' not in kql_query.lower():
            suggestions.append("Consider filtering by authentication result for security analysis")
    elif table_name == "Email":
        if 'sender' not in kql_query.lower() and 'recipient' not in kql_query.lower():
            suggestions.append("Consider including sender or recipient analysis for email threats")

    return {"suggestions": suggestions}

def refine_query(kql_query: str, table_name: str, valid_fields: List[str]) -> str:
    """Attempt to refine/fix the query"""

    refined = kql_query

    # Fix common issues
    lines = refined.split('\n')

    # Ensure first line doesn't have pipe
    if lines and lines[0].strip().startswith('|'):
        lines[0] = lines[0].strip()[1:].strip()

    # Ensure subsequent lines have pipes
    for i in range(1, len(lines)):
        if lines[i].strip() and not lines[i].strip().startswith('|'):
            lines[i] = '| ' + lines[i].strip()

    refined = '\n'.join(lines)

    return refined

# Example usage function for testing
def test_validator():
    """Test the validator with sample query data"""
    test_query_data = {
        "queries": [
            {
                "table": "Email",
                "query": "Email\n| where event_time > ago(7d)\n| summarize count() by sender\n| limit 100",
                "confidence": 0.85
            },
            {
                "table": "AuthenticationEvents", 
                "query": "AuthenticationEvents\n| where timestamp > ago(7d)\n| where result != 'Success'\n| summarize failed_attempts=count() by username, src_ip\n| limit 100",
                "confidence": 0.90
            }
        ]
    }

    result = validate_and_refine_queries(test_query_data)

    print("Validation Results:")
    print(f"Success Rate: {result['validation_summary']['success_rate']}")

    for query in result["validated_queries"]:
        print(f"\nTable: {query['table']}")
        print(f"Validation Passed: {query['validation_passed']}")
        print(f"Score: {query['validation_score']}")
        if query['validation_errors']:
            print(f"Errors: {query['validation_errors']}")
        if query['validation_warnings']:
            print(f"Warnings: {query['validation_warnings']}")
        print("-" * 50)

if __name__ == "__main__":
    test_validator()
