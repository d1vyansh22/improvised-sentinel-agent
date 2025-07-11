"""
LLM Prompt Templates for Threat Intelligence System
"""

from typing import Dict, List
from schema_definitions import AZURE_SENTINEL_TABLES

# Query Enrichment Prompt
QUERY_ENRICHMENT_PROMPT = """You are an expert Azure Sentinel threat intelligence analyst. Your task is to analyze natural language threat hunting queries and provide structured enrichment.

Available Azure Sentinel Tables:
{available_tables}

IoC Type Mapping:
- ip_address: IP addresses, network indicators
- domain: Domain names, DNS queries
- url: Web URLs, links
- email_address: Email addresses, senders, recipients
- file_hash: File hashes (SHA256, MD5)
- process_name: Process names, executables
- hostname: Computer names, endpoints
- username: User accounts, identities
- user_agent: Browser user agents, client strings

Your task:
1. Analyze the user query: "{user_query}"
2. Identify relevant IoC types mentioned or implied
3. Select 1-4 most relevant tables from the available tables
4. Suggest appropriate time range if not specified
5. Provide confidence score (0.0-1.0)

Return ONLY a JSON object with this exact structure:
{{
  "enriched_query": "Clear description of what to search for",
  "selected_tables": ["Table1", "Table2"],
  "ioc_types": ["ioc_type1", "ioc_type2"],
  "time_range": "last 24 hours" or "last 7 days" or specific range,
  "confidence_score": 0.85,
  "reasoning": "Brief explanation of table selection"
}}

Important guidelines:
- Select maximum 4 tables that are most relevant
- Focus on tables that contain the IoCs mentioned in the query
- If query is vague, select most common threat hunting tables
- Time range should be reasonable for the query type
- Confidence score should reflect query clarity and table relevance
"""

# KQL Generation Prompt
KQL_GENERATION_PROMPT = """You are an expert KQL (Kusto Query Language) developer specializing in Azure Sentinel threat hunting queries.

Table: {table_name}
Schema: {table_schema}
Available Fields: {field_list}

Enriched Query Context:
- Search objective: {enriched_query}
- IoC types: {ioc_types}
- Time range: {time_range}

Your task:
Generate a syntactically correct and semantically meaningful KQL query that:
1. Searches the {table_name} table for relevant indicators
2. Includes appropriate time filtering using timestamp fields
3. Filters for the specified IoC types
4. Returns relevant columns for analysis
5. Includes reasonable limits and aggregations where appropriate

KQL Best Practices:
- Use proper datetime filtering with timestamp_1 or similar datetime fields
- Include 'limit' clause to prevent excessive results
- Use appropriate operators (==, contains, has, in~, etc.)
- Include relevant columns in project statements
- Use summarize for aggregations when appropriate

Return ONLY the KQL query string, no explanations or markdown formatting.

Example format:
{table_name}
| where timestamp_1 >= ago(24h)
| where field_name contains "search_term"
| project timestamp_1, relevant_field1, relevant_field2
| limit 100
"""

# Query Validation and Repair Prompt
QUERY_VALIDATION_REPAIR_PROMPT = """You are a KQL (Kusto Query Language) expert specializing in syntax correction and query optimization.

Original Query:
```
{original_query}
```

Validation Errors:
{validation_errors}

Table Schema:
{table_schema}

Your task:
Analyze the validation errors and provide a corrected KQL query that:
1. Fixes all syntax errors
2. Ensures all referenced fields exist in the table schema
3. Uses correct KQL operators and functions
4. Maintains the original query intent
5. Follows KQL best practices

Common fixes:
- Correct field names that don't exist in schema
- Fix operator syntax (==, contains, has, etc.)
- Ensure proper datetime field usage
- Fix function calls and parameters
- Correct table references

If the query cannot be fixed due to fundamental issues, respond with:
UNFIXABLE: [explanation]

Otherwise, return ONLY the corrected KQL query, no explanations or markdown formatting.
"""

# Schema Context Builder
def build_schema_context(table_name: str) -> Dict[str, str]:
    """Build schema context for prompt templates"""
    schema = AZURE_SENTINEL_TABLES.get(table_name, {})

    field_list = []
    for field_name, field_type in schema.get("fields", {}).items():
        field_list.append(f"{field_name} ({field_type})")

    return {
        "table_name": table_name,
        "table_schema": schema,
        "field_list": ", ".join(field_list),
        "description": schema.get("description", ""),
        "primary_iocs": schema.get("primary_iocs", []),
        "sample_query": schema.get("sample_query", "")
    }

# Available Tables Context
def build_available_tables_context() -> str:
    """Build context of all available tables for enrichment"""
    context = []
    for table_name, schema in AZURE_SENTINEL_TABLES.items():
        iocs = ", ".join(schema.get("primary_iocs", []))
        context.append(f"- {table_name}: {schema.get('description', '')} (IoCs: {iocs})")

    return "\n".join(context)

# Prompt formatters
def format_enrichment_prompt(user_query: str) -> str:
    """Format the query enrichment prompt"""
    return QUERY_ENRICHMENT_PROMPT.format(
        user_query=user_query,
        available_tables=build_available_tables_context()
    )

def format_kql_generation_prompt(table_name: str, enriched_query: str, 
                                ioc_types: List[str], time_range: str) -> str:
    """Format the KQL generation prompt"""
    schema_context = build_schema_context(table_name)

    return KQL_GENERATION_PROMPT.format(
        table_name=table_name,
        table_schema=schema_context["table_schema"],
        field_list=schema_context["field_list"],
        enriched_query=enriched_query,
        ioc_types=", ".join(ioc_types),
        time_range=time_range
    )

def format_validation_repair_prompt(original_query: str, validation_errors: List[str], 
                                   table_name: str) -> str:
    """Format the query validation and repair prompt"""
    schema_context = build_schema_context(table_name)

    return QUERY_VALIDATION_REPAIR_PROMPT.format(
        original_query=original_query,
        validation_errors="\n".join(validation_errors),
        table_schema=schema_context["table_schema"]
    )

# System prompts for different LLM providers
SYSTEM_PROMPTS = {
    "gemini": "You are a cybersecurity expert specializing in threat hunting with Azure Sentinel. Provide accurate, actionable KQL queries for security analysis.",
    "openai": "You are an expert security analyst with deep knowledge of Azure Sentinel and KQL. Generate precise, validated queries for threat intelligence analysis."
}
