
"""
BuildToValue Python SDK

Installation:
    pip install buildtovalue

Usage:
    from buildtovalue import BuildToValue
    
    client = BuildToValue(api_key="btv_your_key_here")
    
    result = client.validate(
        text="My CPF is 123.456.789-09",
        session_id="session_123"
    )
    
    if result.action == "BLOCK":
        print(f"Blocked: {result.rationale}")
"""

from typing import Optional, Dict, Any, List
import requests
from dataclasses import dataclass
from enum import Enum

class Action(Enum):
    ALLOW = "ALLOW"
    EDUCATE = "EDUCATE"
    REDACT = "REDACT"
    LOG = "LOG"
    BLOCK = "BLOCK"

@dataclass
class ValidationResult:
    verdict_id: str
    action: Action
    confidence: float
    rationale: str
    processing_time_ms: int
    can_appeal: bool
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ValidationResult':
        return cls(
            verdict_id=data['verdict_id'],
            action=Action(data['action']),
            confidence=data['confidence'],
            rationale=data['rationale'],
            processing_time_ms=data['processing_time_ms'],
            can_appeal=data.get('appeal_info', {}).get('can_appeal', False),
        )

class BuildToValue:
    """BuildToValue API client"""
    
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.buildtovalue.com/v2",
        timeout: int = 10,
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "X-API-Key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "BuildToValue-Python-SDK/2.0.0",
        })
    
    def validate(
        self,
        text: str,
        session_id: str,
        profile: str = "general",
        context: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        """
        Validate user input.
        
        Args:
            text: Input text to validate
            session_id: Unique session identifier
            profile: Policy profile (default: "general")
            context: Additional context (domain, user_role, etc)
        
        Returns:
            ValidationResult object
        
        Raises:
            APIError: If API request fails
        """
        payload = {
            "text": text,
            "session_id": session_id,
            "profile": profile,
        }
        
        if context:
            payload["context"] = context
        
        try:
            response = self.session.post(
                f"{self.base_url}/validate",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return ValidationResult.from_dict(response.json())
        
        except requests.HTTPError as e:
            if e.response.status_code == 429:
                raise RateLimitError(e.response.json())
            elif e.response.status_code == 401:
                raise AuthenticationError("Invalid API key")
            else:
                raise APIError(e.response.json())
        
        except requests.RequestException as e:
            raise APIError({"error": "NETWORK_ERROR", "message": str(e)})
    
    def validate_batch(
        self,
        inputs: List[Dict[str, Any]],
        session_id: str,
        profile: str = "general",
    ) -> List[ValidationResult]:
        """
        Validate multiple inputs in batch.
        
        Args:
            inputs: List of {"id": "...", "text": "..."}
            session_id: Unique session identifier
            profile: Policy profile
        
        Returns:
            List of ValidationResult objects
        """
        payload = {
            "inputs": inputs,
            "session_id": session_id,
            "profile": profile,
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/validate/batch",
                json=payload,
                timeout=self.timeout * 2,  # Batch takes longer
            )
            response.raise_for_status()
            data = response.json()
            return [
                ValidationResult.from_dict(result)
                for result in data['results']
            ]
        
        except requests.HTTPError as e:
            raise APIError(e.response.json())
    
    def submit_appeal(
        self,
        verdict_id: str,
        reason: str,
    ) -> str:
        """
        Submit appeal for a decision.
        
        Args:
            verdict_id: ID of verdict to contest
            reason: Explanation of why decision was wrong
        
        Returns:
            Appeal ID
        """
        payload = {
            "verdict_id": verdict_id,
            "reason": reason,
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/appeals",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()['appeal_id']
        
        except requests.HTTPError as e:
            raise APIError(e.response.json())

# Exceptions
class APIError(Exception):
    """Base API error"""
    def __init__(self, error_data: Dict[str, Any]):
        self.error = error_data.get('error', 'UNKNOWN_ERROR')
        self.message = error_data.get('message', 'Unknown error')
        super().__init__(self.message)

class RateLimitError(APIError):
    """Rate limit exceeded"""
    pass

class AuthenticationError(APIError):
    """Authentication failed"""
    pass