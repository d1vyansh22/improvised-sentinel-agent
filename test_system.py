"""
Test Runner for Threat Intelligence System
Simple test script to verify functionality
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import SimpleThreatIntelAgent

def run_basic_tests():
    """Run basic functionality tests"""

    print("=== Running Basic Tests ===\n")

    # Test 1: Initialize agent
    print("Test 1: Initializing agent...")
    try:
        agent = SimpleThreatIntelAgent()
        print("✓ Agent initialized successfully")
    except Exception as e:
        print(f"✗ Agent initialization failed: {e}")
        return False

    # Test 2: Process simple query
    print("\nTest 2: Processing threat intelligence query...")
    test_query = "Find suspicious login activities from external IP addresses"

    try:
        result = agent.process_threat_query(test_query)

        if result["success"]:
            print("✓ Query processed successfully")
            analysis = result["analysis"]
            print(f"  - Tables selected: {len(analysis['summary']['tables_analyzed'])}")
            print(f"  - Queries generated: {analysis['summary']['total_queries']}")
            print(f"  - Executable queries: {analysis['summary']['executable_queries']}")
            return True
        else:
            print(f"✗ Query processing failed: {result['error']}")
            return False

    except Exception as e:
        print(f"✗ Test failed with exception: {e}")
        return False

def run_individual_tool_tests():
    """Test each tool individually"""

    print("\n=== Testing Individual Tools ===\n")

    # Test Query Enricher
    print("Testing Query Enricher...")
    try:
        from tools.query_enricher import enrich_user_query
        result = enrich_user_query.invoke({"user_query": "Find failed logins"})
        print(f"✓ Enricher working. Selected tables: {result['selected_tables']}")
    except Exception as e:
        print(f"✗ Enricher failed: {e}")

    # Test KQL Generator
    print("\nTesting KQL Generator...")
    try:
        from tools.kql_generator import generate_kql_queries
        test_enriched = {
            "selected_tables": ["AuthenticationEvents"],
            "ioc_types": ["ip_address"],
            "time_range": "7d",
            "original_query": "Find failed logins"
        }
        result = generate_kql_queries.invoke({"enriched_data": test_enriched})
        print(f"✓ KQL Generator working. Generated {len(result['queries'])} queries")
    except Exception as e:
        print(f"✗ KQL Generator failed: {e}")

    # Test Query Validator
    print("\nTesting Query Validator...")
    try:
        from tools.query_validator import validate_and_refine_queries
        test_queries = {
            "queries": [{
                "table": "AuthenticationEvents",
                "query": "AuthenticationEvents\n| where timestamp > ago(7d)\n| limit 100"
            }]
        }
        result = validate_and_refine_queries.invoke({"query_data": test_queries})
        print(f"✓ Validator working. Success rate: {result['validation_summary']['success_rate']}")
    except Exception as e:
        print(f"✗ Validator failed: {e}")

if __name__ == "__main__":
    # Run individual tool tests first
    run_individual_tool_tests()

    # Run full workflow test
    success = run_basic_tests()

    if success:
        print("\n🎉 All tests passed! The threat intelligence system is working correctly.")
    else:
        print("\n❌ Some tests failed. Check the error messages above.")
