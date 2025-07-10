# Simple Threat Intelligence System

A minimal-code threat intelligence system built with **LangChain** and **LangGraph** for local development. This system transforms natural language threat hunting queries into validated KQL queries for Azure Sentinel.

## 🎯 Features

- **3 Specialized Tools** working together:
  1. **Query Enricher**: Analyzes natural language and selects relevant Azure Sentinel tables
  2. **KQL Generator**: Creates semantically correct KQL queries  
  3. **Query Validator**: Validates syntax and provides refinements

- **Out-of-box LangChain/LangGraph functionality**
- **Local development focused** - no deployment complexity
- **Azure Sentinel integration** with 9 security log tables
- **Minimal dependencies** and simple setup

## 🏗️ Architecture

```
User Query → Query Enricher → KQL Generator → Query Validator → Final Analysis
```

The system uses **LangGraph's StateGraph** to orchestrate the tools in a reliable workflow with built-in state management.

## 📁 Project Structure

```
simple_threat_intel/
├── main.py                 # Main LangGraph application
├── requirements.txt        # Dependencies
├── test_system.py         # Test runner
├── .env.example           # Environment template
├── tools/
│   ├── query_enricher.py  # Tool 1: Query enrichment
│   ├── kql_generator.py   # Tool 2: KQL generation  
│   └── query_validator.py # Tool 3: Query validation
└── schemas/
    └── azure_schemas.py   # Azure Sentinel table definitions
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
cd simple_threat_intel
pip install -r requirements.txt
```

### 2. Run the System

```bash
# Test individual components
python test_system.py

# Run the main application with examples
python main.py
```

### 3. Use Programmatically

```python
from main import SimpleThreatIntelAgent

# Initialize the agent
agent = SimpleThreatIntelAgent()

# Process a threat hunting query
result = agent.process_threat_query(
    "Find suspicious email activities from external domains"
)

# Get the analysis
if result["success"]:
    analysis = result["analysis"]
    print(f"Tables to query: {analysis['summary']['tables_analyzed']}")

    # Get executable KQL queries
    for query in analysis["executable_queries"]:
        print(f"Table: {query['table']}")
        print(f"KQL: {query['refined_query']}")
```

## 🔧 How It Works

### 1. Query Enrichment
- Analyzes natural language for IOC types (IP addresses, domains, emails, etc.)
- Selects up to 4 most relevant Azure Sentinel tables
- Adds threat hunting context and time ranges

### 2. KQL Generation  
- Creates table-specific KQL queries based on enriched data
- Includes appropriate filters, aggregations, and time constraints
- Generates contextual queries based on threat patterns

### 3. Query Validation
- Validates KQL syntax and field names
- Checks for performance issues and security concerns
- Provides refinements and suggestions

## 📊 Supported Azure Sentinel Tables

| Table | Focus Area | Key IOC Types |
|-------|------------|---------------|
| PassiveDNS | DNS resolution | IP addresses, domains |
| InboundBrowsing | Web traffic (inbound) | IPs, URLs, user agents |
| OutBoundBrowsing | Web traffic (outbound) | IPs, URLs, user agents |
| ProcessEvents | Process execution | File hashes, hostnames |
| Email | Email communication | Email addresses, domains |
| FileCreationEvents | File operations | File hashes, filenames |
| Employees | User activity | IP addresses, emails |
| IAM | Access management | IPs, hostnames, usernames |
| AuthenticationEvents | Login/auth events | IPs, hostnames, usernames |

## 💡 Example Queries

The system can handle natural language queries like:

- *"Find suspicious email activities from external domains"*
- *"Detect multiple failed login attempts from unknown IP addresses"*  
- *"Identify potential malware file executions on critical servers"*
- *"Look for unusual DNS queries to suspicious domains"*

## 🔍 Sample Output

```python
# Input query
query = "Find failed login attempts from external IPs"

# System output
{
  "summary": {
    "tables_analyzed": ["AuthenticationEvents", "IAM"],
    "executable_queries": 2,
    "time_range": "7d"
  },
  "executable_queries": [
    {
      "table": "AuthenticationEvents",
      "query": "AuthenticationEvents\n| where timestamp > ago(7d)\n| where result != 'Success'\n| where not(ipv4_is_private(src_ip))\n| summarize failed_attempts=count() by username, src_ip\n| limit 100",
      "confidence": 0.92
    }
  ],
  "recommendations": [
    "Consider geo-location analysis for suspicious IP addresses",
    "Execute queries during low-traffic hours for better performance"
  ]
}
```

## 🛠️ Customization

### Adding New Tables
1. Update `schemas/azure_schemas.py` with new table definition
2. Add IOC type mappings and field definitions
3. Update KQL generation logic if needed

### Extending IOC Detection
Modify `identify_ioc_types()` in `azure_schemas.py`:

```python
ioc_keywords = {
    "new_ioc_type": ["keyword1", "keyword2"],
    # ... existing IOC types
}
```

### Custom Query Patterns
Extend `generate_contextual_filters()` in `kql_generator.py`:

```python
if "your_pattern" in query_lower:
    filters.append("| where your_field contains 'pattern'")
```

## 🧪 Testing

Run the test suite to verify functionality:

```bash
python test_system.py
```

This tests:
- Individual tool functionality
- End-to-end workflow
- Query generation and validation
- Error handling

## 🚀 Advanced Usage

### Integration with LLMs (Optional)

The system is designed to work standalone, but you can enhance it with LLMs:

```python
# Add to .env file
OPENAI_API_KEY=your_key_here
# or
GOOGLE_API_KEY=your_key_here

# The tools can then be enhanced with LLM reasoning
```

### Custom Workflow Modifications

Modify the LangGraph workflow in `main.py`:

```python
def _build_workflow(self):
    workflow = StateGraph(ThreatIntelState)

    # Add custom nodes
    workflow.add_node("custom_analysis", self._custom_node)

    # Modify edges
    workflow.add_edge("validate_queries", "custom_analysis")
    workflow.add_edge("custom_analysis", "create_analysis")

    return workflow.compile()
```

## 📚 Learning Resources

- **LangChain Documentation**: [python.langchain.com](https://python.langchain.com)
- **LangGraph Guide**: [langchain-ai.github.io/langgraph](https://langchain-ai.github.io/langgraph)
- **KQL Reference**: [Microsoft KQL Documentation](https://docs.microsoft.com/en-us/azure/kusto/query/)
- **Azure Sentinel**: [Microsoft Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)

## 🤝 Contributing

This is designed as a learning project and foundation for more complex systems. Feel free to:

- Add new IOC detection patterns
- Enhance KQL generation logic
- Improve validation rules
- Add more Azure Sentinel tables
- Create additional tools

## 📝 License

This project is for educational purposes. Use responsibly and in accordance with your organization's security policies.

## 🔗 Related Projects

- **LangChain**: Framework for LLM applications
- **LangGraph**: Stateful multi-actor applications  
- **Azure Sentinel**: Cloud-native SIEM platform
- **KQL**: Kusto Query Language for data analysis

---

**Built with ❤️ using LangChain and LangGraph**

*This system demonstrates how to build sophisticated AI applications with minimal code using out-of-the-box framework functionality.*
