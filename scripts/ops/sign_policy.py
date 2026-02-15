
import hmac
import hashlib
import yaml
from pathlib import Path

def sign_policy(policy_file: Path, signing_key: bytes) -> str:
    """
    Assina policy com HMAC-SHA256.
    
    Garante:
    - Non-repudiation: Comitê não pode negar aprovação
    - Integrity: Mudanças não autorizadas são detectadas
    """
    
    with open(policy_file, 'rb') as f:
        content = f.read()
    
    # Remove campo 'signature' se existir (para recalcular)
    policy_dict = yaml.safe_load(content)
    if 'signature' in policy_dict:
        del policy_dict['signature']
    
    # Serializa deterministicamente (ordem alfabética)
    canonical_yaml = yaml.dump(
        policy_dict,
        sort_keys=True,
        default_flow_style=False
    )
    
    # Calcula HMAC
    signature = hmac.new(
        signing_key,
        canonical_yaml.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # Adiciona signature ao YAML
    policy_dict['signature'] = signature
    
    # Reescreve arquivo
    with open(policy_file, 'w') as f:
        yaml.dump(policy_dict, f, sort_keys=True)
    
    return signature

def verify_policy_signature(policy_file: Path, signing_key: bytes) -> bool:
    """Verifica assinatura de uma policy"""
    
    with open(policy_file, 'r') as f:
        policy_dict = yaml.safe_load(f)
    
    if 'signature' not in policy_dict:
        return False
    
    stored_signature = policy_dict['signature']
    
    # Remove signature e recalcula
    del policy_dict['signature']
    canonical_yaml = yaml.dump(policy_dict, sort_keys=True)
    
    expected_signature = hmac.new(
        signing_key,
        canonical_yaml.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(stored_signature, expected_signature)