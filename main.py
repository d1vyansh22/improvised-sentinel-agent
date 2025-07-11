"""
Main Threat Intelligence System - LangGraph Implementation
This file contains the complete LangGraph workflow for threat intelligence analysis.
"""

import os
import time
import json
import structlog
from typing import Dict, Any, List, TypedDict
from datetime import datetime, timezone
from dotenv import load_dotenv

from langgraph.graph import StateGraph, END
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI

from tools.query_enricher import query_enricher_tool
from tools.kql_generator import kql_generator_tool
from tools.query_validator import query_validator_tool
from utils.models import ThreatIntelligenceResponse
from utils.helpers import (
    SecurityValidator, metrics_collector, generate_query_id, 
    format_processing_time, create_error_response
)

# Load environment variables
load_dotenv()

# Configure logging
logger = structlog.get_logger()

class ThreatIntelligenceState(TypedDict):
    """State definition for the threat intelligence workflow"""
    user_query: str
    enriched_data: Dict[str, Any]
    generated_queries: List[Dict[str, Any]]
    validated_queries: List[Dict[str, Any]]
    final_output: Dict[str, Any]
    errors: List[str]
    attempts: int
    query_id: str
    start_time: float
    metadata: Dict[str, Any]

# LangGraph Node Functions
def enrich_query_node(state: ThreatIntelligenceState) -> Dict[str, Any]:
    """
    Node 1: Enrich natural language query using LLM
    """
    try:
        logger.info("Starting query enrichment", query_id=state["query_id"])

        # Call query enricher tool
        result = query_enricher_tool(state["user_query"])

        if result["success"]:
            return {
                "enriched_data": result["enriched_data"],
                "metadata": {
                    **state.get("metadata", {}),
                    "enrichment_success": True,
                    "enrichment_time": time.time()
                }
            }
        else:
            return {
                "errors": state.get("errors", []) + [f"Query enrichment failed: {result.get('error', 'Unknown error')}"],
                "metadata": {
                    **state.get("metadata", {}),
                    "enrichment_success": False
                }
            }

    except Exception as e:
        logger.error("Query enrichment node failed", error=str(e), query_id=state["query_id"])
        return {
            "errors": state.get("errors", []) + [f"Query enrichment node error: {str(e)}"]
        }

def generate_kql_node(state: ThreatIntelligenceState) -> Dict[str, Any]:
    """
    Node 2: Generate KQL queries using LLM
    """
    try:
        logger.info("Starting KQL generation", query_id=state["query_id"])

        # Call KQL generator tool
        result = kql_generator_tool(state["enriched_data"])

        if result["success"]:
            return {
                "generated_queries": result["generated_queries"],
                "metadata": {
                    **state.get("metadata", {}),
                    "generation_success": True,
                    "generation_time": time.time(),
                    "total_tables": result["total_tables"],
                    "successful_generations": result["successful_generations"]
                }
            }
        else:
            return {
                "errors": state.get("errors", []) + [f"KQL generation failed: {result.get('error', 'Unknown error')}"],
                "metadata": {
                    **state.get("metadata", {}),
                    "generation_success": False
                }
            }

    except Exception as e:
        logger.error("KQL generation node failed", error=str(e), query_id=state["query_id"])
        return {
            "errors": state.get("errors", []) + [f"KQL generation node error: {str(e)}"]
        }

def validate_queries_node(state: ThreatIntelligenceState) -> Dict[str, Any]:
    """
    Node 3: Validate and repair KQL queries using LLM reflection
    """
    try:
        logger.info("Starting query validation", query_id=state["query_id"])

        # Call query validator tool
        result = query_validator_tool(state["generated_queries"])

        if result["success"]:
            return {
                "validated_queries": result["validated_queries"],
                "attempts": state.get("attempts", 0) + 1,
                "metadata": {
                    **state.get("metadata", {}),
                    "validation_success": True,
                    "validation_time": time.time(),
                    "validation_success_rate": result["success_rate"],
                    "total_validations": result["total_queries"]
                }
            }
        else:
            return {
                "errors": state.get("errors", []) + [f"Query validation failed: {result.get('error', 'Unknown error')}"],
                "attempts": state.get("attempts", 0) + 1,
                "metadata": {
                    **state.get("metadata", {}),
                    "validation_success": False
                }
            }

    except Exception as e:
        logger.error("Query validation node failed", error=str(e), query_id=state["query_id"])
        return {
            "errors": state.get("errors", []) + [f"Query validation node error: {str(e)}"],
            "attempts": state.get("attempts", 0) + 1
        }

def finalize_output_node(state: ThreatIntelligenceState) -> Dict[str, Any]:
    """
    Node 4: Create final output and summary
    """
    try:
        logger.info("Finalizing output", query_id=state["query_id"])

        # Calculate processing time
        processing_time = format_processing_time(state["start_time"])

        # Create summary
        successful_queries = sum(1 for q in state.get("validated_queries", []) if q.get("is_valid", False))
        total_queries = len(state.get("validated_queries", []))

        summary = {
            "query_id": state["query_id"],
            "processing_time_ms": processing_time,
            "success": len(state.get("errors", [])) == 0,
            "tables_analyzed": len(state.get("enriched_data", {}).get("selected_tables", [])),
            "queries_generated": len(state.get("generated_queries", [])),
            "queries_validated": successful_queries,
            "total_queries": total_queries,
            "validation_success_rate": successful_queries / total_queries if total_queries > 0 else 0,
            "errors": state.get("errors", [])
        }

        # Create final output
        final_output = {
            "success": len(state.get("errors", [])) == 0,
            "user_query": state["user_query"],
            "query_id": state["query_id"],
            "processing_time_ms": processing_time,
            "enrichment": state.get("enriched_data", {}),
            "generated_queries": state.get("generated_queries", []),
            "validated_queries": state.get("validated_queries", []),
            "executable_queries": [q for q in state.get("validated_queries", []) if q.get("is_valid", False)],
            "summary": summary,
            "errors": state.get("errors", []),
            "metadata": state.get("metadata", {})
        }

        # Record metrics
        if final_output["success"]:
            tables_used = state.get("enriched_data", {}).get("selected_tables", [])
            metrics_collector.record_query_success(state["query_id"], state["start_time"], tables_used)
        else:
            error_type = "validation_failed" if state.get("validated_queries") else "generation_failed"
            metrics_collector.record_query_failure(state["query_id"], state["start_time"], error_type)

        logger.info("Output finalized", 
                   query_id=state["query_id"],
                   success=final_output["success"],
                   processing_time=processing_time)

        return {"final_output": final_output}

    except Exception as e:
        logger.error("Output finalization failed", error=str(e), query_id=state["query_id"])
        error_output = create_error_response(f"Output finalization failed: {str(e)}", state["query_id"])
        return {"final_output": error_output}

# Conditional edge function for validation loop
def should_retry_validation(state: ThreatIntelligenceState) -> str:
    """
    Determine if validation should be retried based on current state
    """
    # Check if there are validation errors and we haven't exceeded max attempts
    max_attempts = int(os.getenv("MAX_VALIDATION_ATTEMPTS", "3"))
    current_attempts = state.get("attempts", 0)

    # Get validation results
    validated_queries = state.get("validated_queries", [])
    has_invalid_queries = any(not q.get("is_valid", False) for q in validated_queries)

    # Retry if we have invalid queries and haven't exceeded max attempts
    if has_invalid_queries and current_attempts < max_attempts:
        logger.info("Retrying validation", 
                   attempt=current_attempts + 1, 
                   max_attempts=max_attempts,
                   query_id=state.get("query_id"))
        return "generate_kql"  # Go back to generation for another attempt

    logger.info("Proceeding to finalization", 
               attempt=current_attempts, 
               query_id=state.get("query_id"))
    return "finalize_output"

# Build the LangGraph workflow
def build_workflow() -> StateGraph:
    """Build the LangGraph workflow"""
    workflow = StateGraph(ThreatIntelligenceState)

    # Add nodes
    workflow.add_node("enrich_query", enrich_query_node)
    workflow.add_node("generate_kql", generate_kql_node)
    workflow.add_node("validate_queries", validate_queries_node)
    workflow.add_node("finalize_output", finalize_output_node)

    # Add edges
    workflow.set_entry_point("enrich_query")
    workflow.add_edge("enrich_query", "generate_kql")
    workflow.add_edge("generate_kql", "validate_queries")

    # Add conditional edge for validation loop
    workflow.add_conditional_edges(
        "validate_queries",
        should_retry_validation,
        {
            "generate_kql": "generate_kql",
            "finalize_output": "finalize_output"
        }
    )

    workflow.add_edge("finalize_output", END)

    return workflow

# Compile the graph
graph = build_workflow().compile()

class ThreatIntelligenceAgent:
    """Main agent class for threat intelligence analysis"""

    def __init__(self):
        self.security_validator = SecurityValidator()
        self.workflow = graph

    def process_query(self, user_query: str) -> Dict[str, Any]:
        """
        Process a threat intelligence query through the complete workflow

        Args:
            user_query: Natural language threat hunting query

        Returns:
            Complete threat intelligence analysis result
        """
        # Generate query ID and start time
        query_id = generate_query_id()
        start_time = time.time()

        try:
            # Sanitize input
            sanitized_query = self.security_validator.sanitize_input(user_query)
            if not sanitized_query:
                return create_error_response("Invalid or empty query", query_id)

            # Record query start
            metrics_collector.record_query_start(query_id)

            # Initialize state
            initial_state = ThreatIntelligenceState(
                user_query=sanitized_query,
                enriched_data={},
                generated_queries=[],
                validated_queries=[],
                final_output={},
                errors=[],
                attempts=0,
                query_id=query_id,
                start_time=start_time,
                metadata={"start_time": start_time}
            )

            # Execute workflow
            result = self.workflow.invoke(initial_state)

            return result["final_output"]

        except Exception as e:
            logger.error("Workflow execution failed", error=str(e), query_id=query_id)
            metrics_collector.record_query_failure(query_id, start_time, "workflow_error")
            return create_error_response(f"Workflow execution failed: {str(e)}", query_id)

    def get_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        return metrics_collector.get_metrics_summary()

# Example usage and testing
def main():
    """Main function for testing the system"""
    print("🚀 Starting Threat Intelligence System Test")

    # Initialize agent
    agent = ThreatIntelligenceAgent()

    # Test queries
    test_queries = [
        "Find suspicious email activities from external domains",
        "Look for failed login attempts from unusual IP addresses",
        "Detect potential malware execution on endpoints",
        "Investigate DNS tunneling activities"
    ]

    for i, query in enumerate(test_queries, 1):
        print(f"\n{'='*50}")
        print(f"Test {i}/{len(test_queries)}: {query}")
        print(f"{'='*50}")

        result = agent.process_query(query)

        print(f"✅ Success: {result['success']}")
        print(f"⏱️  Processing time: {result.get('processing_time_ms', 0):.2f}ms")

        if result['success']:
            summary = result['summary']
            print(f"📊 Tables analyzed: {summary['tables_analyzed']}")
            print(f"🔍 Queries generated: {summary['queries_generated']}")
            print(f"✅ Queries validated: {summary['queries_validated']}")
            print(f"📈 Success rate: {summary['validation_success_rate']:.2%}")

            print("\n🔍 Executable Queries:")
            for query_data in result.get('executable_queries', []):
                print(f"  Table: {query_data.get('table', 'Unknown')}")
                print(f"  Query: {query_data.get('final_query', 'No query')[:100]}...")
                print(f"  Confidence: {query_data.get('confidence_final', 0):.2f}")
                print()
        else:
            print(f"❌ Errors: {result.get('errors', [])}")

    # Print final metrics
    print(f"\n{'='*50}")
    print("📊 Final System Metrics")
    print(f"{'='*50}")
    metrics = agent.get_metrics()
    print(f"Success rate: {metrics['success_rate']:.2%}")
    print(f"Average processing time: {metrics['avg_processing_time_seconds']:.2f}s")
    print(f"Total queries processed: {metrics['total_queries']}")
    print(f"Total LLM calls: {metrics['llm_calls']}")

if __name__ == "__main__":
    main()