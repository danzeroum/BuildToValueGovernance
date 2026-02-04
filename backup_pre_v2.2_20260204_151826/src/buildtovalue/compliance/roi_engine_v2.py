
from buildtovalue_compliance_ffi import calculate_penalties_batch

def calculate_roi(threats: list[dict]) -> dict:
    """
    Calculate ROI for batch of threats (single FFI call).
    
    Args:
        threats: List of {"threat_type": str, "framework": str}
    
    Returns:
        {"total_roi_usd": Decimal, "count": int}
    """
    # Single FFI call for 100+ threats
    result = calculate_penalties_batch(threats)
    
    return {
        "total_roi_usd": Decimal(result["total_roi_usd"]),
        "count": result["count"],
    }

# USAGE
threats = [
    {"threat_type": "pii_leakage", "framework": "LGPD"},
    {"threat_type": "shadow_ai", "framework": "EU_AI_ACT"},
    # ... 98 more threats
]

roi = calculate_roi(threats)
print(f"Total ROI: ${roi['total_roi_usd']:,.2f}")