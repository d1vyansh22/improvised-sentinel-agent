"""
Simple Threat Intelligence System
Main LangGraph application using out-of-box functionality
"""

import os
from typing import TypedDict, List, Dict, Any
from dotenv import load_dotenv

from langchain_core.messages import HumanMessage, AIMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from typing_extensions import Annotated

# Import our custom tools
from tools.query_enricher import enrich_user_query
from tools.kql_generator import generate_kql_queries  
from tools.query_validator import validate_and_refine_queries

# Load environment variables
load_dotenv()

class ThreatIntelState(TypedDict):
    """State for the threat intelligence workflow"""
    messages: Annotated[List[HumanMessage | AIMessage], add_messages]
    user_query: str
    enriched_data: Dict[str, Any]
    generated_queries: Dict[str, Any]
    validated_queries: Dict[str, Any]
    final_analysis: Dict[str, Any]
    current_step: str

class SimpleThreatIntelAgent:
    """Simple threat intelligence agent using LangGraph"""

    def __init__(self):
        self.workflow = self._build_workflow()

    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow"""

        # Create the state graph
        workflow = StateGraph(ThreatIntelState)

        # Add nodes
        workflow.add_node("enrich_query", self._enrich_query_node)
        workflow.add_node("generate_kql", self._generate_kql_node)
        workflow.add_node("validate_queries", self._validate_queries_node)
        workflow.add_node("create_analysis", self._create_analysis_node)

        # Define the workflow edges
        workflow.add_edge(START, "enrich_query")
        workflow.add_edge("enrich_query", "generate_kql")
        workflow.add_edge("generate_kql", "validate_queries")
        workflow.add_edge("validate_queries", "create_analysis")
        workflow.add_edge("create_analysis", END)

        return workflow.compile()

    def _enrich_query_node(self, state: ThreatIntelState) -> ThreatIntelState:
        """Node to enrich the user query"""

        user_query = state.get("user_query", "")
        if not user_query and state.get("messages"):
            # Extract query from messages if not provided directly
            last_message = state["messages"][-1]
            if isinstance(last_message, HumanMessage):
                user_query = last_message.content

        # Use our custom tool to enrich the query
        enriched_data = enrich_user_query.invoke({"user_query": user_query})

        # Add system message about enrichment
        enrichment_msg = AIMessage(
            content=f"Query enriched. Selected tables: {enriched_data['selected_tables']}. "
                   f"IOC types identified: {enriched_data['ioc_types']}"
        )

        return {
            **state,
            "user_query": user_query,
            "enriched_data": enriched_data,
            "current_step": "enrichment_complete",
            "messages": state.get("messages", []) + [enrichment_msg]
        }

    def _generate_kql_node(self, state: ThreatIntelState) -> ThreatIntelState:
        """Node to generate KQL queries"""

        enriched_data = state.get("enriched_data", {})

        # Generate KQL queries using our custom tool
        generated_queries = generate_kql_queries.invoke({"enriched_data": enriched_data})

        # Create message about generation
        generation_msg = AIMessage(
            content=f"Generated {generated_queries['total_tables']} KQL queries for threat hunting analysis."
        )

        return {
            **state,
            "generated_queries": generated_queries,
            "current_step": "kql_generation_complete",
            "messages": state.get("messages", []) + [generation_msg]
        }

    def _validate_queries_node(self, state: ThreatIntelState) -> ThreatIntelState:
        """Node to validate the generated queries"""

        generated_queries = state.get("generated_queries", {})

        # Validate queries using our custom tool
        validated_queries = validate_and_refine_queries.invoke({"query_data": generated_queries})

        # Create validation message
        summary = validated_queries["validation_summary"]
        validation_msg = AIMessage(
            content=f"Validation complete. Success rate: {summary['success_rate']}. "
                   f"Average validation score: {summary['avg_validation_score']}"
        )

        return {
            **state,
            "validated_queries": validated_queries,
            "current_step": "validation_complete", 
            "messages": state.get("messages", []) + [validation_msg]
        }

    def _create_analysis_node(self, state: ThreatIntelState) -> ThreatIntelState:
        """Node to create final threat intelligence analysis"""

        user_query = state.get("user_query", "")
        enriched_data = state.get("enriched_data", {})
        validated_queries = state.get("validated_queries", {})

        # Create comprehensive analysis
        final_analysis = self._generate_final_analysis(user_query, enriched_data, validated_queries)

        # Create final analysis message
        analysis_msg = AIMessage(
            content=f"Threat intelligence analysis complete. "
                   f"Ready to execute {len(final_analysis['executable_queries'])} validated queries."
        )

        return {
            **state,
            "final_analysis": final_analysis,
            "current_step": "analysis_complete",
            "messages": state.get("messages", []) + [analysis_msg]
        }

    def _generate_final_analysis(self, user_query: str, enriched_data: Dict, 
                                validated_queries: Dict) -> Dict[str, Any]:
        """Generate comprehensive threat intelligence analysis"""

        executable_queries = [
            q for q in validated_queries.get("validated_queries", [])
            if q.get("validation_passed", False)
        ]

        analysis = {
            "summary": {
                "original_request": user_query,
                "analysis_scope": enriched_data.get("ioc_types", []),
                "tables_analyzed": enriched_data.get("selected_tables", []),
                "time_range": enriched_data.get("time_range", "7d"),
                "total_queries": len(validated_queries.get("validated_queries", [])),
                "executable_queries": len(executable_queries)
            },
            "executable_queries": executable_queries,
            "recommendations": self._generate_recommendations(enriched_data, validated_queries),
            "next_steps": [
                "Execute the validated KQL queries in Azure Sentinel",
                "Review results for potential threats and anomalies", 
                "Correlate findings across multiple data sources",
                "Create alerts or investigate further based on findings"
            ]
        }

        return analysis

    def _generate_recommendations(self, enriched_data: Dict, validated_queries: Dict) -> List[str]:
        """Generate actionable recommendations"""

        recommendations = []

        # General recommendations
        recommendations.append("Execute queries during low-traffic hours for better performance")

        # IOC-specific recommendations
        ioc_types = enriched_data.get("ioc_types", [])
        if "ip_address" in ioc_types:
            recommendations.append("Consider geo-location analysis for suspicious IP addresses")
        if "email" in ioc_types:
            recommendations.append("Review email attachment analysis and domain reputation")
        if "file_hash" in ioc_types:
            recommendations.append("Cross-reference file hashes with threat intelligence feeds")

        # Validation-based recommendations
        validation_summary = validated_queries.get("validation_summary", {})
        if validation_summary.get("success_rate", 0) < 1.0:
            recommendations.append("Review failed validations and refine queries as needed")

        return recommendations

    def process_threat_query(self, user_query: str) -> Dict[str, Any]:
        """
        Process a threat intelligence query through the complete workflow

        Args:
            user_query: Natural language threat hunting request

        Returns:
            Complete analysis with validated KQL queries and recommendations
        """

        # Initialize state
        initial_state = ThreatIntelState(
            messages=[HumanMessage(content=user_query)],
            user_query=user_query,
            enriched_data={},
            generated_queries={},
            validated_queries={},
            final_analysis={},
            current_step="initialized"
        )

        # Run the workflow
        try:
            result = self.workflow.invoke(initial_state)
            return {
                "success": True,
                "analysis": result.get("final_analysis", {}),
                "workflow_messages": [msg.content for msg in result.get("messages", [])],
                "metadata": {
                    "enriched_data": result.get("enriched_data", {}),
                    "validation_summary": result.get("validated_queries", {}).get("validation_summary", {})
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "analysis": {}
            }

def main():
    """Main function to demonstrate the threat intelligence system"""

    print("=== Simple Threat Intelligence System ===\n")

    # Initialize the agent
    agent = SimpleThreatIntelAgent()

    # Example queries to test
    example_queries = [
        "Find suspicious email activities from external domains in the last week",
        "Detect multiple failed login attempts from unknown IP addresses", 
        "Identify potential malware file executions on critical servers",
        "Look for unusual DNS queries to suspicious domains"
    ]

    print("Testing with example queries:\n")

    for i, query in enumerate(example_queries, 1):
        print(f"Query {i}: {query}")
        print("-" * 80)

        # Process the query
        result = agent.process_threat_query(query)

        if result["success"]:
            analysis = result["analysis"]
            print(f"✓ Analysis successful")
            print(f"  Tables analyzed: {analysis['summary']['tables_analyzed']}")
            print(f"  Executable queries: {analysis['summary']['executable_queries']}")
            print(f"  Key recommendations: {len(analysis['recommendations'])}")

            # Show first executable query as example
            if analysis["executable_queries"]:
                first_query = analysis["executable_queries"][0]
                print(f"  Sample KQL query for {first_query['table']}:")
                print(f"    {first_query['refined_query'][:100]}...")
        else:
            print(f"✗ Analysis failed: {result['error']}")

        print("\n")

if __name__ == "__main__":
    main()
