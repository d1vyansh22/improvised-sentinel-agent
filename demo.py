"""
Demo Script for Simple Threat Intelligence System
Interactive demonstration of system capabilities
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from main import SimpleThreatIntelAgent

def interactive_demo():
    """Interactive demo allowing user input"""

    print("🛡️  Simple Threat Intelligence System - Interactive Demo")
    print("=" * 60)
    print("This system converts natural language queries into KQL for Azure Sentinel")
    print("Type 'quit' to exit\n")

    agent = SimpleThreatIntelAgent()

    while True:
        # Get user input
        user_query = input("Enter your threat hunting query: ").strip()

        if user_query.lower() in ['quit', 'exit', 'q']:
            print("👋 Thanks for using the Threat Intelligence System!")
            break

        if not user_query:
            continue

        print(f"\n🔍 Processing: '{user_query}'")
        print("-" * 50)

        # Process the query
        result = agent.process_threat_query(user_query)

        if result["success"]:
            analysis = result["analysis"]
            summary = analysis["summary"]

            print(f"✅ Analysis Complete!")
            print(f"   📊 Tables Selected: {', '.join(summary['tables_analyzed'])}")
            print(f"   🔢 Total Queries: {summary['total_queries']}")
            print(f"   ✓ Executable Queries: {summary['executable_queries']}")
            print(f"   ⏰ Time Range: {summary['time_range']}")

            # Show executable queries
            if analysis["executable_queries"]:
                print(f"\n📝 Generated KQL Queries:")
                for i, query in enumerate(analysis["executable_queries"], 1):
                    print(f"\n   Query {i} - {query['table']} (Confidence: {query.get('confidence', 'N/A')}):")

                    # Show refined query with proper formatting
                    kql_lines = query['refined_query'].split('\n')
                    for line in kql_lines:
                        if line.strip():
                            print(f"      {line}")

            # Show recommendations
            if analysis["recommendations"]:
                print(f"\n💡 Recommendations:")
                for rec in analysis["recommendations"][:3]:  # Show top 3
                    print(f"   • {rec}")

        else:
            print(f"❌ Error: {result['error']}")

        print("\n" + "=" * 60 + "\n")

def preset_demo():
    """Demo with preset queries"""

    print("🛡️  Simple Threat Intelligence System - Preset Demo")
    print("=" * 60)

    agent = SimpleThreatIntelAgent()

    demo_queries = [
        ("Suspicious Email Activity", "Find suspicious email activities from external domains in the last week"),
        ("Failed Authentication", "Detect multiple failed login attempts from unknown IP addresses"),
        ("Malware Detection", "Identify potential malware file executions on critical servers"),
        ("DNS Anomalies", "Look for unusual DNS queries to suspicious domains")
    ]

    for title, query in demo_queries:
        print(f"\n🎯 Demo: {title}")
        print(f"Query: '{query}'")
        print("-" * 50)

        result = agent.process_threat_query(query)

        if result["success"]:
            analysis = result["analysis"]
            summary = analysis["summary"]

            print(f"✅ Tables: {', '.join(summary['tables_analyzed'])}")
            print(f"📊 Executable Queries: {summary['executable_queries']}")

            # Show one sample query
            if analysis["executable_queries"]:
                sample_query = analysis["executable_queries"][0]
                print(f"📝 Sample KQL for {sample_query['table']}:")

                # Show first few lines
                lines = sample_query['refined_query'].split('\n')[:3]
                for line in lines:
                    if line.strip():
                        print(f"   {line}")
                if len(sample_query['refined_query'].split('\n')) > 3:
                    print("   ...")
        else:
            print(f"❌ Error: {result['error']}")

        print()

def main():
    """Main demo function"""

    print("Select demo mode:")
    print("1. Interactive Mode (enter your own queries)")
    print("2. Preset Demo (see example queries)")
    print("3. Exit")

    while True:
        choice = input("\nEnter choice (1-3): ").strip()

        if choice == "1":
            interactive_demo()
            break
        elif choice == "2":
            preset_demo()
            break
        elif choice == "3":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
