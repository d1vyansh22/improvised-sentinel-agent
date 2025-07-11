"""
Pydantic models for the threat intelligence system
"""

from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime

class ThreatIntelligenceState(BaseModel):
    """Main state model for the LangGraph workflow"""
    user_query: str
    enriched_data: Dict[str, Any] = Field(default_factory=dict)
    generated_queries: List[Dict[str, Any]] = Field(default_factory=list)
    validated_queries: List[Dict[str, Any]] = Field(default_factory=list)
    final_output: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    attempts: int = Field(default=0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class EnrichmentResult(BaseModel):
    """Result from query enrichment step"""
    enriched_query: str
    selected_tables: List[str] = Field(max_length=4)
    ioc_types: List[str]
    time_range: Optional[str] = None
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning: Optional[str] = None

class KQLQueryResult(BaseModel):
    """Result from KQL generation step"""
    table: str
    query: str
    confidence: float = Field(ge=0.0, le=1.0)
    is_valid: bool = Field(default=False)
    errors: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ValidationResult(BaseModel):
    """Result from query validation step"""
    original_query: str
    final_query: str
    is_valid: bool
    validation_errors: List[str] = Field(default_factory=list)
    refinement_iterations: int = Field(default=0)
    confidence_final: float = Field(ge=0.0, le=1.0)
    analyzer_response: Optional[Dict[str, Any]] = None

class ThreatIntelligenceResponse(BaseModel):
    """Final response from the threat intelligence system"""
    success: bool
    user_query: str
    processing_time_ms: float
    enrichment: EnrichmentResult
    queries: List[KQLQueryResult]
    validated_queries: List[ValidationResult]
    summary: Dict[str, Any]
    errors: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class LLMConfig(BaseModel):
    """Configuration for LLM providers"""
    provider: str = Field(default="gemini")
    model: str = Field(default="gemini-2.0-flash")
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, gt=0)
    timeout: int = Field(default=30, gt=0)
    max_retries: int = Field(default=3, ge=0)

class RetryConfig(BaseModel):
    """Configuration for retry mechanisms"""
    max_attempts: int = Field(default=3, ge=1)
    backoff_factor: float = Field(default=2.0, ge=1.0)
    max_backoff: int = Field(default=60, gt=0)
    jitter: bool = Field(default=True)

class ValidationConfig(BaseModel):
    """Configuration for query validation"""
    kql_analyzer_endpoint: str = Field(default="http://localhost:8000/api/analyze")
    timeout: int = Field(default=15, gt=0)
    max_validation_attempts: int = Field(default=3, ge=1)
    enable_syntax_check: bool = Field(default=True)
    enable_semantic_check: bool = Field(default=True)

class SystemConfig(BaseModel):
    """Overall system configuration"""
    llm_config: LLMConfig = Field(default_factory=LLMConfig)
    retry_config: RetryConfig = Field(default_factory=RetryConfig)
    validation_config: ValidationConfig = Field(default_factory=ValidationConfig)
    log_level: str = Field(default="INFO")
    enable_tracing: bool = Field(default=True)
    max_tables_per_query: int = Field(default=4, ge=1, le=9)
