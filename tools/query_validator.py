"""
Query Validator Tool - Validates and repairs KQL queries using LLM reflection
"""

import json
import requests
import structlog
from typing import Dict, Any, List
from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from utils.models import ValidationResult
from utils.prompts import format_validation_repair_prompt
from utils.helpers import SecurityValidator, LLMResponseParser, metrics_collector
from schema_definitions import get_table_schema

logger = structlog.get_logger()

class QueryValidatorTool:
    """Tool for validating and repairing KQL queries using LLM reflection"""

    def __init__(self, llm_primary, llm_fallback=None, max_attempts=3):
        self.llm_primary = llm_primary
        self.llm_fallback = llm_fallback
        self.max_attempts = max_attempts
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

    def _call_kql_analyzer(self, query: str, table_name: str) -> Dict[str, Any]:
        """Call KQL analyzer API for validation (mock implementation)"""
        try:
            import os
            endpoint = os.getenv("KQL_ANALYZER_ENDPOINT", "http://localhost:8000/api/analyze")
            timeout = int(os.getenv("KQL_ANALYZER_TIMEOUT", "15"))

            # Mock KQL analyzer response for demo purposes
            # In production, this would call a real KQL analyzer service
            mock_response = self._mock_kql_analyzer(query, table_name)

            # Uncomment below for real KQL analyzer call
            # payload = {"query": query, "environment": "sentinel"}
            # response = requests.post(endpoint, json=payload, timeout=timeout)
            # return response.json()

            return mock_response

        except requests.RequestException as e:
            logger.error("KQL analyzer call failed", error=str(e))
            return {
                "parsing_errors": [f"Analyzer service unavailable: {str(e)}"],
                "output_columns": {},
                "referenced_tables": [],
                "referenced_functions": [],
                "referenced_columns": []
            }

    def _mock_kql_analyzer(self, query: str, table_name: str) -> Dict[str, Any]:
        """Mock KQL analyzer for demo purposes"""
        parsing_errors = []

        # Basic validation checks
        if not query:
            parsing_errors.append("Query is empty")
        elif table_name not in query:
            parsing_errors.append(f"Query does not reference expected table '{table_name}'")
        elif "|" not in query:
            parsing_errors.append("Query missing pipe operators")
        elif "where" not in query.lower():
            parsing_errors.append("Query should include 'where' clause for filtering")

        # Check for common syntax errors
        if query.count("(") != query.count(")"):
            parsing_errors.append("Unbalanced parentheses")

        # Check for field existence (simplified)
        table_schema = get_table_schema(table_name)
        if table_schema:
            available_fields = list(table_schema.get("fields", {}).keys())
            # Simple check for field references
            for field in available_fields:
                if field in query and field not in available_fields:
                    parsing_errors.append(f"Field '{field}' not found in table schema")

        return {
            "parsing_errors": parsing_errors,
            "output_columns": {"timestamp_1": "datetime", "result": "string"} if not parsing_errors else {},
            "referenced_tables": [table_name] if table_name in query else [],
            "referenced_functions": [],
            "referenced_columns": available_fields[:3] if table_schema else []
        }

    def _validate_with_reflection(self, query: str, table_name: str) -> ValidationResult:
        """Validate query with LLM reflection loop"""
        original_query = query
        current_query = query
        attempts = 0

        while attempts < self.max_attempts:
            attempts += 1
            metrics_collector.record_validation_attempt(False)  # Will update if successful

            logger.info("Validation attempt", attempt=attempts, table=table_name)

            # Call KQL analyzer
            analyzer_result = self._call_kql_analyzer(current_query, table_name)

            # Check if validation passed
            if not analyzer_result.get("parsing_errors", []):
                logger.info("Query validation successful", 
                           attempts=attempts, 
                           table=table_name)
                metrics_collector.record_validation_attempt(True)

                return ValidationResult(
                    original_query=original_query,
                    final_query=current_query,
                    is_valid=True,
                    validation_errors=[],
                    refinement_iterations=attempts - 1,
                    confidence_final=0.9,
                    analyzer_response=analyzer_result
                )

            # If max attempts reached, return with errors
            if attempts >= self.max_attempts:
                logger.warning("Max validation attempts reached", 
                              attempts=attempts, 
                              table=table_name)

                return ValidationResult(
                    original_query=original_query,
                    final_query=current_query,
                    is_valid=False,
                    validation_errors=analyzer_result.get("parsing_errors", []),
                    refinement_iterations=attempts - 1,
                    confidence_final=0.3,
                    analyzer_response=analyzer_result
                )

            # Use LLM reflection to fix errors
            try:
                repair_prompt = format_validation_repair_prompt(
                    current_query, 
                    analyzer_result.get("parsing_errors", []),
                    table_name
                )

                repair_response = self._make_llm_call(repair_prompt)

                # Extract repaired query
                repaired_query = self.parser.extract_kql_from_response(repair_response)

                # Check if LLM indicated the query is unfixable
                if "UNFIXABLE" in repair_response.upper():
                    logger.warning("LLM indicated query is unfixable", 
                                  table=table_name, 
                                  errors=analyzer_result.get("parsing_errors", []))

                    return ValidationResult(
                        original_query=original_query,
                        final_query=current_query,
                        is_valid=False,
                        validation_errors=analyzer_result.get("parsing_errors", []) + ["Query deemed unfixable by LLM"],
                        refinement_iterations=attempts - 1,
                        confidence_final=0.1,
                        analyzer_response=analyzer_result
                    )

                # Update current query for next iteration
                current_query = repaired_query

                logger.info("Query repaired by LLM", 
                           attempt=attempts, 
                           table=table_name)

            except Exception as e:
                logger.error("Query repair failed", 
                           error=str(e), 
                           attempt=attempts, 
                           table=table_name)

                return ValidationResult(
                    original_query=original_query,
                    final_query=current_query,
                    is_valid=False,
                    validation_errors=analyzer_result.get("parsing_errors", []) + [f"Repair failed: {str(e)}"],
                    refinement_iterations=attempts - 1,
                    confidence_final=0.2,
                    analyzer_response=analyzer_result
                )

        # Should never reach here, but just in case
        return ValidationResult(
            original_query=original_query,
            final_query=current_query,
            is_valid=False,
            validation_errors=["Max attempts exceeded"],
            refinement_iterations=attempts,
            confidence_final=0.1,
            analyzer_response={}
        )

    def validate_and_repair_queries(self, generated_queries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate and repair generated KQL queries

        Args:
            generated_queries: List of generated KQL queries from generator tool

        Returns:
            Dictionary containing validation results
        """
        try:
            validated_queries = []
            successful_validations = 0

            for query_data in generated_queries:
                if not query_data.get("query"):
                    # Skip empty queries
                    validated_queries.append({
                        "original_query": "",
                        "final_query": "",
                        "is_valid": False,
                        "validation_errors": ["Query is empty"],
                        "refinement_iterations": 0,
                        "confidence_final": 0.0,
                        "table": query_data.get("table", "unknown")
                    })
                    continue

                # Validate query with reflection
                validation_result = self._validate_with_reflection(
                    query_data["query"],
                    query_data["table"]
                )

                result_dict = validation_result.model_dump()
                result_dict["table"] = query_data["table"]
                validated_queries.append(result_dict)

                if validation_result.is_valid:
                    successful_validations += 1

            success_rate = successful_validations / len(generated_queries) if generated_queries else 0

            logger.info("Query validation completed", 
                       total_queries=len(generated_queries),
                       successful=successful_validations,
                       success_rate=success_rate)

            return {
                "validated_queries": validated_queries,
                "total_queries": len(generated_queries),
                "successful_validations": successful_validations,
                "success_rate": success_rate,
                "success": True,
                "metadata": {
                    "validation_summary": {
                        "total": len(generated_queries),
                        "valid": successful_validations,
                        "invalid": len(generated_queries) - successful_validations,
                        "success_rate": success_rate
                    }
                }
            }

        except Exception as e:
            logger.error("Query validation failed", error=str(e))
            return {
                "validated_queries": [],
                "total_queries": 0,
                "successful_validations": 0,
                "success_rate": 0.0,
                "success": False,
                "error": str(e)
            }

# Create tool instance function for LangGraph
@tool
def query_validator_tool(generated_queries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate and repair KQL queries using LLM reflection.

    Args:
        generated_queries: List of generated KQL queries from generator tool

    Returns:
        Dictionary with validation results and repaired queries
    """
    try:
        import os
        from dotenv import load_dotenv
        load_dotenv()

        if not os.getenv("GOOGLE_API_KEY") and not os.getenv("OPENAI_API_KEY"):
            return {
                "validated_queries": [],
                "total_queries": 0,
                "successful_validations": 0,
                "success_rate": 0.0,
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
                max_tokens=4096,
                timeout=30
            )

        max_attempts = int(os.getenv("MAX_VALIDATION_ATTEMPTS", "3"))
        validator = QueryValidatorTool(gemini_llm, openai_llm, max_attempts)

        return validator.validate_and_repair_queries(generated_queries)

    except Exception as e:
        logger.error("Failed to initialize query validator", error=str(e))
        return {
            "validated_queries": [],
            "total_queries": 0,
            "successful_validations": 0,
            "success_rate": 0.0,
            "success": False,
            "error": f"Tool initialization failed: {str(e)}"
        }

# Example usage and testing
if __name__ == "__main__":
    # Test the tool with sample generated queries
    test_queries = [
        {
            "table": "Email",
            "query": "Email | where sender contains 'suspicious' | project sender, subject, timestamp",
            "confidence": 0.8,
            "is_valid": False,
            "errors": []
        },
        {
            "table": "AuthenticationEvents",
            "query": "AuthenticationEvents | where result == 'Failed' | summarize count() by username",
            "confidence": 0.9,
            "is_valid": False,
            "errors": []
        }
    ]

    print("=== Testing Query Validator ===")
    result = query_validator_tool(test_queries)
    print(f"Success: {result['success']}")
    print(f"Success rate: {result['success_rate']:.2f}")

    if result['success']:
        for validated in result['validated_queries']:
            print(f"\nTable: {validated['table']}")
            print(f"Valid: {validated['is_valid']}")
            print(f"Iterations: {validated['refinement_iterations']}")
            print(f"Final confidence: {validated['confidence_final']:.2f}")
            if validated['validation_errors']:
                print(f"Errors: {validated['validation_errors']}")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")
