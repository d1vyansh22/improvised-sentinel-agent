"""
KQL Generator Tool - Converts enriched queries into KQL queries for Azure Sentinel
"""

import json
import structlog
from typing import Dict, Any, List
from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from utils.models import KQLQueryResult
from utils.prompts import format_kql_generation_prompt
from utils.helpers import SecurityValidator, LLMResponseParser, metrics_collector
from schema_definitions import get_table_schema

logger = structlog.get_logger()

class KQLGeneratorTool:
    """Tool for generating KQL queries from enriched threat intelligence requests"""

    def __init__(self, llm_primary, llm_fallback=None):
        self.llm_primary = llm_primary
        self.llm_fallback = llm_fallback
        self.security_validator = SecurityValidator()
        self.parser = LLMResponseParser()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def _make_llm_call(self, prompt: str) -> str:
        """Make LLM call with retry logic"""
        try:
            response = self.llm_primary.invoke(prompt)
            metrics_collector.record_llm_call("gemini", "gemini-2.0-flash", True)
            return response.content
        except Exception as e:
            logger.warning("Primary LLM call failed", error=str(e))
            metrics_collector.record_llm_call("gemini", "gemini-2.0-flash", False)

            if self.llm_fallback:
                try:
                    response = self.llm_fallback.invoke(prompt)
                    metrics_collector.record_llm_call("openai", "gpt-4o", True)
                    logger.info("Fallback LLM call successful")
                    return response.content
                except Exception as fallback_error:
                    logger.error("Fallback LLM call failed", error=str(fallback_error))
                    metrics_collector.record_llm_call("openai", "gpt-4o", False)
                    raise
            raise

    def _calculate_query_confidence(self, query: str, table_name: str) -> float:
        """Calculate confidence score for generated query"""
        if not query or not table_name:
            return 0.0

        confidence = 0.5  # Base confidence

        # Check for proper table reference
        if table_name in query:
            confidence += 0.2

        # Check for time filtering
        time_keywords = ["ago(", "timestamp", "datetime", "TimeGenerated"]
        if any(keyword in query for keyword in time_keywords):
            confidence += 0.2

        # Check for proper KQL structure
        kql_keywords = ["where", "project", "summarize", "limit", "sort", "take"]
        keyword_count = sum(1 for keyword in kql_keywords if keyword in query.lower())
        confidence += min(keyword_count * 0.05, 0.2)

        # Check for proper operators
        operators = ["==", "!=", "contains", "has", "in~", "startswith", "endswith"]
        if any(op in query for op in operators):
            confidence += 0.1

        return min(confidence, 1.0)

    def _validate_query_syntax(self, query: str, table_name: str) -> tuple[bool, List[str]]:
        """Basic syntax validation for KQL query"""
        errors = []

        if not query:
            errors.append("Query is empty")
            return False, errors

        # Check for table reference
        if table_name not in query:
            errors.append(f"Query does not reference table '{table_name}'")

        # Check for basic KQL structure
        if "|" not in query:
            errors.append("Query appears to be missing KQL pipe operators")

        # Check for balanced parentheses
        if query.count("(") != query.count(")"):
            errors.append("Unbalanced parentheses in query")

        # Check for dangerous operations
        is_safe, safety_warnings = self.security_validator.validate_kql_safety(query)
        if not is_safe:
            errors.extend(safety_warnings)

        return len(errors) == 0, errors

    def generate_kql_for_table(self, table_name: str, enriched_query: str, 
                               ioc_types: List[str], time_range: str) -> KQLQueryResult:
        """Generate KQL query for a specific table"""
        try:
            # Get table schema
            table_schema = get_table_schema(table_name)
            if not table_schema:
                raise ValueError(f"Schema not found for table: {table_name}")

            # Build KQL generation prompt
            prompt = format_kql_generation_prompt(table_name, enriched_query, ioc_types, time_range)

            logger.info("Generating KQL query", table=table_name, iocs=ioc_types)

            # Make LLM call
            response = self._make_llm_call(prompt)

            # Extract KQL from response
            kql_query = self.parser.extract_kql_from_response(response)

            # Validate query
            is_valid, errors = self._validate_query_syntax(kql_query, table_name)

            # Calculate confidence
            confidence = self._calculate_query_confidence(kql_query, table_name)

            result = KQLQueryResult(
                table=table_name,
                query=kql_query,
                confidence=confidence,
                is_valid=is_valid,
                errors=errors,
                metadata={
                    "ioc_types": ioc_types,
                    "time_range": time_range,
                    "schema_fields": list(table_schema.get("fields", {}).keys())
                }
            )

            logger.info("KQL query generated", 
                       table=table_name, 
                       valid=is_valid, 
                       confidence=confidence,
                       errors=len(errors))

            return result

        except Exception as e:
            logger.error("KQL generation failed", table=table_name, error=str(e))
            return KQLQueryResult(
                table=table_name,
                query="",
                confidence=0.0,
                is_valid=False,
                errors=[str(e)],
                metadata={}
            )

    def generate_kql_queries(self, enriched_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate KQL queries from enriched threat intelligence data

        Args:
            enriched_data: Output from query enricher tool

        Returns:
            Dictionary containing generated KQL queries
        """
        try:
            # Extract enrichment data
            selected_tables = enriched_data.get("selected_tables", [])
            enriched_query = enriched_data.get("enriched_query", "")
            ioc_types = enriched_data.get("ioc_types", [])
            time_range = enriched_data.get("time_range", "last 24 hours")

            if not selected_tables:
                raise ValueError("No tables selected for KQL generation")

            # Generate queries for each table
            generated_queries = []
            successful_generations = 0

            for table_name in selected_tables:
                result = self.generate_kql_for_table(table_name, enriched_query, ioc_types, time_range)
                generated_queries.append(result.model_dump())

                if result.is_valid:
                    successful_generations += 1

            logger.info("KQL generation completed", 
                       total_tables=len(selected_tables),
                       successful=successful_generations)

            return {
                "generated_queries": generated_queries,
                "total_tables": len(selected_tables),
                "successful_generations": successful_generations,
                "success": True,
                "metadata": {
                    "enriched_query": enriched_query,
                    "ioc_types": ioc_types,
                    "time_range": time_range
                }
            }

        except Exception as e:
            logger.error("KQL generation failed", error=str(e))
            return {
                "generated_queries": [],
                "total_tables": 0,
                "successful_generations": 0,
                "success": False,
                "error": str(e)
            }

# Create tool instance function for LangGraph
@tool
def kql_generator_tool(enriched_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate KQL queries from enriched threat intelligence data.

    Args:
        enriched_data: Dictionary containing enriched query data from query enricher

    Returns:
        Dictionary with generated KQL queries for each selected table
    """
    try:
        import os
        from dotenv import load_dotenv
        load_dotenv()

        if not os.getenv("GOOGLE_API_KEY") and not os.getenv("OPENAI_API_KEY"):
            return {
                "generated_queries": [],
                "total_tables": 0,
                "successful_generations": 0,
                "success": False,
                "error": "GOOGLE_API_KEY or OPENAI_API_KEY is not set. Please add it to your .env file."
            }

        gemini_llm = ChatGoogleGenerativeAI(
            model="gemini-2.0-flash",
            temperature=0.1,
            max_tokens=4096,
            timeout=30
        )

        openai_llm = None
        if os.getenv("OPENAI_API_KEY"):
            openai_llm = ChatOpenAI(
                model="gpt-4o",
                temperature=0.1,
                timeout=30
            )

        generator = KQLGeneratorTool(gemini_llm, openai_llm)
        return generator.generate_kql_queries(enriched_data)

    except Exception as e:
        logger.error("Failed to initialize KQL generator", error=str(e))
        return {
            "generated_queries": [],
            "total_tables": 0,
            "successful_generations": 0,
            "success": False,
            "error": f"Tool initialization failed: {str(e)}"
        }

# Example usage and testing
if __name__ == "__main__":
    # Test the tool with sample enriched data
    test_enriched_data = {
        "enriched_query": "Find suspicious email activities from external domains",
        "selected_tables": ["Email", "PassiveDNS"],
        "ioc_types": ["email_address", "domain"],
        "time_range": "last 24 hours",
        "confidence_score": 0.85
    }

    print("=== Testing KQL Generator ===")
    result = kql_generator_tool(str(test_enriched_data))
    if isinstance(result, dict):
        print(f"Success: {result.get('success')}")
        print(f"Total tables: {result.get('total_tables')}")
        print(f"Successful generations: {result.get('successful_generations')}")
    if not isinstance(result, dict):
        print("Error: Unexpected result type from kql_generator_tool")
    elif result.get("success"):
        for query_data in result.get("generated_queries", []):
            print(f"\nTable: {query_data.get('table')}")
            print(f"Valid: {query_data.get('is_valid')}")
            print(f"Confidence: {query_data.get('confidence', 0):.2f}")
            print(f"Query: {query_data['query'][:200]}...")
            if query_data['errors']:
                print(f"Errors: {query_data['errors']}")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")
