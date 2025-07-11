"""
Interactive Demo for the Threat Intelligence System
Run this to test the system with sample queries
"""

import os
import sys
import time
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def print_banner():
    """Print system banner"""
    print("=" * 60)
    print("🛡️  THREAT INTELLIGENCE SYSTEM DEMO")
    print("=" * 60)
    print("🚀 LangGraph + Gemini AI for Security Analysis")
    print("📊 Convert Natural Language → KQL Queries")
    print("🔍 Full LLM Integration with Validation Loop")
    print("=" * 60)

def print_query_result(result, query_num, total_queries):
    """Print formatted query result"""
    print(f"\n{'='*50}")
    print(f"📋 Query {query_num}/{total_queries} Results")
    print(f"{'='*50}")

    print(f"✅ Success: {result['success']}")
    print(f"⏱️  Processing Time: {result.get('processing_time_ms', 0):.2f}ms")
    print(f"🆔 Query ID: {result.get('query_id', 'N/A')}")

    if result['success']:
        summary = result.get('summary', {})
        print(f"\n📊 Summary:")
        print(f"   Tables Analyzed: {summary.get('tables_analyzed', 0)}")
        print(f"   Queries Generated: {summary.get('queries_generated', 0)}")
        print(f"   Queries Validated: {summary.get('queries_validated', 0)}")
        print(f"   Success Rate: {summary.get('validation_success_rate', 0):.2%}")

        # Show enrichment details
        enrichment = result.get('enrichment', {})
        if enrichment:
            print(f"\n🔍 Query Enrichment:")
            print(f"   Selected Tables: {enrichment.get('selected_tables', [])}")
            print(f"   IoC Types: {enrichment.get('ioc_types', [])}")
            print(f"   Time Range: {enrichment.get('time_range', 'N/A')}")
            print(f"   Confidence: {enrichment.get('confidence_score', 0):.2f}")

        # Show executable queries
        executable_queries = result.get('executable_queries', [])
        if executable_queries:
            print(f"\n🔧 Executable KQL Queries:")
            for i, query_data in enumerate(executable_queries, 1):
                print(f"\n   Query {i} - Table: {query_data.get('table', 'Unknown')}")
                print(f"   Confidence: {query_data.get('confidence_final', 0):.2f}")
                query_text = query_data.get('final_query', 'No query available')
                if len(query_text) > 100:
                    query_text = query_text[:100] + "..."
                print(f"   KQL: {query_text}")
        else:
            print("\n⚠️  No executable queries generated")
    else:
        errors = result.get('errors', [])
        print(f"\n❌ Errors ({len(errors)}):")
        for error in errors:
            print(f"   - {error}")

def run_interactive_demo():
    """Run interactive demo"""
    try:
        from main import ThreatIntelligenceAgent

        print_banner()
        print("\n🔧 Initializing Threat Intelligence Agent...")

        # Check environment variables
        required_env_vars = ['GOOGLE_API_KEY']
        missing_vars = [var for var in required_env_vars if not os.getenv(var)]

        if missing_vars:
            print(f"❌ Missing required environment variables: {missing_vars}")
            print("\n📋 Setup Instructions:")
            print("1. Copy .env.example to .env")
            print("2. Add your Google API key to .env")
            print("3. Run the demo again")
            return

        agent = ThreatIntelligenceAgent()
        print("✅ Agent initialized successfully!")

        # Sample queries
        sample_queries = [
            "Find suspicious email activities from external domains",
            "Look for failed login attempts from unusual IP addresses", 
            "Detect potential malware execution on endpoints",
            "Investigate DNS tunneling activities",
            "Search for privilege escalation attempts",
            "Find unauthorized file access patterns"
        ]

        while True:
            print("\n" + "="*60)
            print("🎯 THREAT INTELLIGENCE QUERY OPTIONS")
            print("="*60)

            print("\n📋 Sample Queries:")
            for i, query in enumerate(sample_queries, 1):
                print(f"   {i}. {query}")

            print(f"\n   {len(sample_queries) + 1}. Enter custom query")
            print(f"   {len(sample_queries) + 2}. Run all sample queries")
            print(f"   {len(sample_queries) + 3}. Show system metrics")
            print(f"   0. Exit")

            try:
                choice = input("\n🔍 Select option: ").strip()

                if choice == "0":
                    print("\n👋 Goodbye!")
                    break
                elif choice == str(len(sample_queries) + 1):
                    # Custom query
                    custom_query = input("\n💭 Enter your threat hunting query: ").strip()
                    if custom_query:
                        print(f"\n🔄 Processing: {custom_query}")
                        result = agent.process_query(custom_query)
                        print_query_result(result, 1, 1)
                    else:
                        print("❌ Query cannot be empty")

                elif choice == str(len(sample_queries) + 2):
                    # Run all samples
                    print(f"\n🔄 Processing all {len(sample_queries)} sample queries...")
                    total_time = 0
                    successful_queries = 0

                    for i, query in enumerate(sample_queries, 1):
                        print(f"\n🔄 Processing query {i}/{len(sample_queries)}: {query}")
                        start_time = time.time()
                        result = agent.process_query(query)
                        processing_time = time.time() - start_time
                        total_time += processing_time

                        if result['success']:
                            successful_queries += 1

                        print_query_result(result, i, len(sample_queries))

                        # Small delay between queries
                        if i < len(sample_queries):
                            time.sleep(1)

                    # Print overall summary
                    print(f"\n{'='*60}")
                    print("📊 BATCH PROCESSING SUMMARY")
                    print(f"{'='*60}")
                    print(f"Total Queries: {len(sample_queries)}")
                    print(f"Successful: {successful_queries}")
                    print(f"Failed: {len(sample_queries) - successful_queries}")
                    print(f"Success Rate: {successful_queries/len(sample_queries):.2%}")
                    print(f"Total Time: {total_time:.2f}s")
                    print(f"Average Time: {total_time/len(sample_queries):.2f}s")

                elif choice == str(len(sample_queries) + 3):
                    # Show metrics
                    print("\n📊 System Metrics:")
                    metrics = agent.get_metrics()
                    print(f"   Success Rate: {metrics.get('success_rate', 0):.2%}")
                    print(f"   Total Queries: {metrics.get('total_queries', 0)}")
                    print(f"   LLM Calls: {metrics.get('llm_calls', 0)}")
                    print(f"   Avg Processing Time: {metrics.get('avg_processing_time_seconds', 0):.2f}s")

                    most_used = metrics.get('most_used_tables', [])
                    if most_used:
                        print(f"   Most Used Tables:")
                        for table, count in most_used[:3]:
                            print(f"     - {table}: {count} times")

                elif choice.isdigit() and 1 <= int(choice) <= len(sample_queries):
                    # Run specific sample query
                    query_idx = int(choice) - 1
                    query = sample_queries[query_idx]
                    print(f"\n🔄 Processing: {query}")
                    result = agent.process_query(query)
                    print_query_result(result, 1, 1)

                else:
                    print("❌ Invalid option. Please try again.")

            except KeyboardInterrupt:
                print("\n\n👋 Demo interrupted by user. Goodbye!")
                break
            except Exception as e:
                print(f"\n❌ An error occurred: {str(e)}")
                print("Please try again or contact support.")

    except ImportError as e:
        print(f"❌ Failed to import required modules: {str(e)}")
        print("\n📋 Setup Instructions:")
        print("1. Install requirements: pip install -r requirements.txt")
        print("2. Set up environment variables")
        print("3. Run the demo again")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")

if __name__ == "__main__":
    run_interactive_demo()