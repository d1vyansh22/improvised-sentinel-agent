"""
Query Enricher Tool - Converts natural language to structured threat intelligence queries
"""

import json
import structlog
from typing import Dict, Any, List
from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from utils.models import EnrichmentResult
from utils.prompts import format_enrichment_prompt
from utils.helpers import SecurityValidator, LLMResponseParser, metrics_collector
from schema_definitions import get_all_table_names, get_tables_by_ioc

logger = structlog.get_logger()

class QueryEnricherTool:
    """Tool for enriching natural language queries into structured threat intelligence requests"""

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

    def _validate_enrichment_result(self, result: Dict[str, Any]) -> EnrichmentResult:
        """Validate and create enrichment result"""
        # Ensure selected tables exist
        all_tables = get_all_table_names()
        selected_tables = result.get("selected_tables", [])
        valid_tables = [t for t in selected_tables if t in all_tables]

        if len(valid_tables) == 0:
            # Default to most common tables if none selected
            valid_tables = ["Email", "ProcessEvents", "AuthenticationEvents", "OutboundBrowsing"][:4]
            logger.warning("No valid tables selected, using defaults", defaults=valid_tables)

        # Limit to maximum 4 tables
        valid_tables = valid_tables[:4]

        # Validate IoC types
        valid_ioc_types = ["ip_address", "domain", "url", "email_address", "file_hash", 
                          "process_name", "hostname", "username", "user_agent"]
        ioc_types = result.get("ioc_types", [])
        filtered_iocs = [ioc for ioc in ioc_types if ioc in valid_ioc_types]

        if not filtered_iocs:
            # Infer IoC types from selected tables
            filtered_iocs = ["ip_address", "hostname", "username"]
            logger.info("No valid IoC types found, using defaults", defaults=filtered_iocs)

        # Validate confidence score
        confidence = result.get("confidence_score", 0.7)
        if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 1:
            confidence = 0.7

        return EnrichmentResult(
            enriched_query=result.get("enriched_query", "General threat hunting query"),
            selected_tables=valid_tables,
            ioc_types=filtered_iocs,
            time_range=result.get("time_range", "last 24 hours"),
            confidence_score=confidence,
            reasoning=result.get("reasoning", "Automated table selection based on query analysis")
        )

    def enrich_query(self, user_query: str) -> Dict[str, Any]:
        """
        Enrich natural language query into structured threat intelligence request

        Args:
            user_query: Natural language threat hunting query

        Returns:
            Dictionary containing enriched query data
        """
        try:
            # Sanitize input
            sanitized_query = self.security_validator.sanitize_input(user_query)
            if not sanitized_query:
                raise ValueError("Query is empty or contains only invalid characters")

            # Build enrichment prompt
            prompt = format_enrichment_prompt(sanitized_query)
            logger.info("Starting query enrichment", query=sanitized_query[:100])

            # Make LLM call
            response = self._make_llm_call(prompt)

            # Parse response
            parsed_result = self.parser.extract_json_from_response(response)
            if not parsed_result:
                raise ValueError("Failed to parse LLM response as JSON")

            # Validate and create result
            enrichment_result = self._validate_enrichment_result(parsed_result)

            logger.info("Query enrichment completed successfully", 
                       tables=enrichment_result.selected_tables,
                       iocs=enrichment_result.ioc_types,
                       confidence=enrichment_result.confidence_score)

            return {
                "enriched_data": enrichment_result.model_dump(),
                "success": True,
                "processing_time_ms": 0  # Will be updated by caller
            }

        except Exception as e:
            logger.error("Query enrichment failed", error=str(e), query=user_query[:100])
            return {
                "enriched_data": {},
                "success": False,
                "error": str(e),
                "processing_time_ms": 0
            }

# Create tool instance function for LangGraph
@tool
def query_enricher_tool(user_query: str) -> Dict[str, Any]:
    """
    Enrich natural language threat hunting query into structured request.

    Args:
        user_query: Natural language description of threat hunting needs

    Returns:
        Dictionary with enriched query data including selected tables and IoC types
    """
    # Initialize LLM clients
    try:
        import os
        from dotenv import load_dotenv
        load_dotenv()

        if not os.getenv("GOOGLE_API_KEY") and not os.getenv("OPENAI_API_KEY"):
            return {
                "enriched_data": {},
                "success": False,
                "error": "GOOGLE_API_KEY or OPENAI_API_KEY is not set. Please add it to your .env file.",
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

        enricher = QueryEnricherTool(gemini_llm, openai_llm)
        return enricher.enrich_query(user_query)

    except Exception as e:
        logger.error("Failed to initialize query enricher", error=str(e))
        return {
            "enriched_data": {},
            "success": False,
            "error": f"Tool initialization failed: {str(e)}"
        }

# Example usage and testing
if __name__ == "__main__":
    # Test the tool
    test_queries = [
        "Find suspicious email activities from external domains",
        "Look for failed login attempts from unusual IP addresses",
        "Detect potential malware execution on endpoints",
        "Investigate DNS tunneling activities"
    ]

    for query in test_queries:
        print(f"\n=== Testing: {query} ===")
        result = query_enricher_tool(query)
        print(f"Success: {result['success']}")
        if result['success']:
            enriched = result['enriched_data']
            print(f"Tables: {enriched['selected_tables']}")
            print(f"IoCs: {enriched['ioc_types']}")
            print(f"Confidence: {enriched['confidence_score']}")
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")
