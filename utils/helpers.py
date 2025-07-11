"""
Helper functions and utilities for the threat intelligence system
"""

import json
import re
import time
import structlog
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

class SecurityValidator:
    """Security validation utilities for input sanitization"""

    DANGEROUS_PATTERNS = [
        r"ignore\s+previous\s+instructions",
        r"system\s*:",
        r"assistant\s*:",
        r"<\s*script",
        r"javascript:",
        r"data:text/html",
        r"\x00",  # null bytes
        r"\.\./"  # path traversal
    ]

    DANGEROUS_KQL_OPERATIONS = [
        "drop", "delete", "create", "alter", "update",
        "exec", "execute", "invoke", "eval", "import"
    ]

    @staticmethod
    def sanitize_input(user_input: str) -> str:
        """Sanitize user input to prevent injection attacks"""
        if not user_input:
            return ""

        # Remove dangerous patterns
        sanitized = user_input
        for pattern in SecurityValidator.DANGEROUS_PATTERNS:
            sanitized = re.sub(pattern, "", sanitized, flags=re.IGNORECASE)

        # Limit input length
        max_length = int(os.getenv("MAX_INPUT_LENGTH", "2000"))
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]

        # Remove control characters except newlines and tabs
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', sanitized)

        return sanitized.strip()

    @staticmethod
    def validate_kql_safety(kql_query: str) -> Tuple[bool, List[str]]:
        """Validate KQL query for potentially dangerous operations"""
        if not kql_query:
            return True, []

        warnings = []
        query_lower = kql_query.lower()

        # Check for dangerous operations
        for operation in SecurityValidator.DANGEROUS_KQL_OPERATIONS:
            if operation in query_lower:
                warnings.append(f"Potentially dangerous operation detected: {operation}")

        # Check for restricted patterns
        restricted_patterns = [
            r"_internal",
            r"admin",
            r"config",
            r"secret",
            r"password",
            r"token",
            r"key"
        ]

        for pattern in restricted_patterns:
            if re.search(pattern, query_lower):
                warnings.append(f"Access to restricted resource pattern: {pattern}")

        return len(warnings) == 0, warnings

class LLMResponseParser:
    """Utilities for parsing LLM responses"""

    @staticmethod
    def extract_json_from_response(response_text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from LLM response, handling various formats"""
        if not response_text:
            return None

        # Try to parse as direct JSON
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            pass

        # Try to extract JSON from code blocks
        json_match = re.search(r'```(?:json)?\n?({.*?})\n?```', response_text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to extract JSON from text
        json_match = re.search(r'{.*?}', response_text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        logger.warning("Failed to extract JSON from LLM response", response=response_text[:200])
        return None

    @staticmethod
    def extract_kql_from_response(response_text: str) -> str:
        """Extract KQL query from LLM response"""
        if not response_text:
            return ""

        # Remove markdown formatting
        response_text = response_text.strip()

        # Remove code block markers
        if response_text.startswith("```") and response_text.endswith("```"):
            lines = response_text.split("\n")
            if len(lines) > 2:
                response_text = "\n".join(lines[1:-1])

        # Remove common prefixes
        prefixes_to_remove = [
            "KQL Query:",
            "Query:",
            "Here's the KQL query:",
            "The KQL query is:",
        ]

        for prefix in prefixes_to_remove:
            if response_text.startswith(prefix):
                response_text = response_text[len(prefix):].strip()

        return response_text.strip()

class MetricsCollector:
    """Collect and track system metrics"""

    def __init__(self):
        self.metrics = {
            "total_queries": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "total_processing_time": 0,
            "llm_calls": 0,
            "validation_attempts": 0,
            "table_usage": {},
            "error_types": {}
        }

    def record_query_start(self, query_id: str):
        """Record the start of a query"""
        self.metrics["total_queries"] += 1
        return time.time()

    def record_query_success(self, query_id: str, start_time: float, tables_used: List[str]):
        """Record successful query completion"""
        self.metrics["successful_queries"] += 1
        processing_time = time.time() - start_time
        self.metrics["total_processing_time"] += processing_time

        # Track table usage
        for table in tables_used:
            self.metrics["table_usage"][table] = self.metrics["table_usage"].get(table, 0) + 1

        logger.info("Query completed successfully", 
                   query_id=query_id, 
                   processing_time=processing_time,
                   tables_used=tables_used)

    def record_query_failure(self, query_id: str, start_time: float, error_type: str):
        """Record failed query"""
        self.metrics["failed_queries"] += 1
        processing_time = time.time() - start_time
        self.metrics["total_processing_time"] += processing_time

        # Track error types
        self.metrics["error_types"][error_type] = self.metrics["error_types"].get(error_type, 0) + 1

        logger.error("Query failed", 
                    query_id=query_id, 
                    processing_time=processing_time,
                    error_type=error_type)

    def record_llm_call(self, provider: str, model: str, success: bool):
        """Record LLM API call"""
        self.metrics["llm_calls"] += 1
        logger.debug("LLM call recorded", provider=provider, model=model, success=success)

    def record_validation_attempt(self, success: bool):
        """Record validation attempt"""
        self.metrics["validation_attempts"] += 1
        logger.debug("Validation attempt recorded", success=success)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get current metrics summary"""
        success_rate = 0
        if self.metrics["total_queries"] > 0:
            success_rate = self.metrics["successful_queries"] / self.metrics["total_queries"]

        avg_processing_time = 0
        if self.metrics["total_queries"] > 0:
            avg_processing_time = self.metrics["total_processing_time"] / self.metrics["total_queries"]

        return {
            "success_rate": success_rate,
            "avg_processing_time_seconds": avg_processing_time,
            "total_queries": self.metrics["total_queries"],
            "llm_calls": self.metrics["llm_calls"],
            "validation_attempts": self.metrics["validation_attempts"],
            "most_used_tables": sorted(self.metrics["table_usage"].items(), 
                                     key=lambda x: x[1], reverse=True)[:5],
            "common_errors": sorted(self.metrics["error_types"].items(), 
                                  key=lambda x: x[1], reverse=True)[:3]
        }

class ConfigManager:
    """Configuration management utilities"""

    @staticmethod
    def load_config() -> Dict[str, Any]:
        """Load configuration from environment variables"""
        return {
            "llm_config": {
                "provider": os.getenv("LLM_PROVIDER", "gemini"),
                "model": os.getenv("LLM_MODEL", "gemini-2.0-flash"),
                "temperature": float(os.getenv("LLM_TEMPERATURE", "0.1")),
                "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "4096")),
                "timeout": int(os.getenv("LLM_TIMEOUT", "30"))
            },
            "validation_config": {
                "kql_analyzer_endpoint": os.getenv("KQL_ANALYZER_ENDPOINT", "http://localhost:8000/api/analyze"),
                "timeout": int(os.getenv("KQL_ANALYZER_TIMEOUT", "15")),
                "max_attempts": int(os.getenv("MAX_VALIDATION_ATTEMPTS", "3"))
            },
            "retry_config": {
                "max_attempts": int(os.getenv("RETRY_MAX_ATTEMPTS", "3")),
                "backoff_factor": float(os.getenv("RETRY_BACKOFF_FACTOR", "2.0")),
                "max_backoff": int(os.getenv("RETRY_MAX_BACKOFF", "60"))
            },
            "tracing_config": {
                "enabled": os.getenv("LANGSMITH_TRACING", "false").lower() == "true",
                "project": os.getenv("LANGSMITH_PROJECT", "threat-intelligence-system")
            }
        }

def generate_query_id() -> str:
    """Generate unique query ID"""
    return f"query_{int(time.time() * 1000)}"

def format_processing_time(start_time: float) -> float:
    """Calculate processing time in milliseconds"""
    return (time.time() - start_time) * 1000

def create_error_response(error_message: str, query_id: str = None) -> Dict[str, Any]:
    """Create standardized error response"""
    return {
        "success": False,
        "error": error_message,
        "query_id": query_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "queries": [],
        "metadata": {}
    }

# Initialize global metrics collector
metrics_collector = MetricsCollector()
