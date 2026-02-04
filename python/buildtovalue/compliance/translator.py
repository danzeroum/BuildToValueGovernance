"""
Compliance Translator v2.1
Converts PDF regulations into YAML Policy Cards using LLM.

DESIGN PRINCIPLE:
- Rust  = Enforce the compiled policy (deterministic)
- Python = Generate the policy (LLM-based, non-deterministic)
"""
import os

import openai
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
import logging
import PyPDF2

logger = logging.getLogger(__name__)

class ComplianceTranslator:
    """
    Translates regulatory PDFs into BuildToValue Policy Cards.
    
    Example:
        translator = ComplianceTranslator(model="gpt-4o", api_key="sk-...")
        yaml_policy = translator.translate_pdf(
            pdf_path="LGPD_Art20.pdf",
            framework="LGPD"
        )
        translator.save_yaml(yaml_policy, "policies/lgpd_art20.yaml")
    """
    
    def __init__(self, model: str = "gpt-4o", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.prompt_template = self._load_prompt_template()
        
        if not self.api_key:
            raise ValueError("OpenAI API key required (set OPENAI_API_KEY env var)")
        
        openai.api_key = self.api_key
    
    def _load_prompt_template(self) -> str:
        return """
You are a legal compliance expert specializing in AI governance.

TASK: Convert the following regulatory text into a BuildToValue Policy Card (YAML).

INPUT:
Framework: {framework}
Regulatory Text:
{regulatory_text}

OUTPUT FORMAT (YAML):
```yaml
name: "Policy Name"
framework: "{framework}"
article: "Art. X"
description: "Brief description"
rules:
  - id: "rule_001"
    action: "BLOCK"  # ALLOW, LOG, EDUCATE, REDACT, BLOCK
    priority: 100
    condition: "has_pii and risk_level == 'HIGH'"
    rationale: "Article X prohibits..."
domain_config:
  healthcare:
    risk_multiplier: 1.5
    education_message: "This violates {framework} Article X..."
```

REQUIREMENTS:
- Extract ONLY enforceable rules (not aspirational goals)
- Map to actionable conditions (use Python syntax)
- Include rationale with article reference
- Be conservative: if ambiguous, use EDUCATE or LOG

OUTPUT (YAML only, no explanations):
"""
    
    def translate_pdf(self, pdf_path: Path, framework: str) -> str:
        """
        Traduz PDF regulatório → YAML Policy Card.
        
        Args:
            pdf_path: Caminho para PDF
            framework: Nome do framework (LGPD, EU_AI_ACT, etc.)
        
        Returns:
            YAML string completo
        
        Raises:
            ValueError: Se PDF inválido ou LLM retornar erro
        """
        logger.info(f"Translating {pdf_path} ({framework})...")
        
        # 1. Extrai texto do PDF
        text = self._extract_pdf_text(pdf_path)
        logger.debug(f"Extracted {len(text)} characters from PDF")
        
        # 2. Gera YAML via LLM
        yaml_content = self._generate_yaml_via_llm(text, framework)
        
        # 3. Valida YAML
        self._validate_yaml(yaml_content)
        
        logger.info(f"✅ Translation completed: {framework}")
        return yaml_content
    
    def _extract_pdf_text(self, pdf_path: Path) -> str:
        """Extrai texto do PDF."""
        pdf_path = Path(pdf_path)
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF not found: {pdf_path}")
        
        text_parts = []
        with open(pdf_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                text_parts.append(page.extract_text())
        
        return "\n".join(text_parts)
    
    def _generate_yaml_via_llm(self, text: str, framework: str) -> str:
        """Usa OpenAI para gerar YAML."""
        prompt = self.prompt_template.format(
            framework=framework,
            regulatory_text=text[:8000]  # Limita para evitar token overflow
        )
        
        response = openai.ChatCompletion.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a compliance expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,  # Baixa temperatura para consistência
            max_tokens=2000
        )
        
        yaml_content = response.choices[0].message.content
        
        # Remove markdown code blocks se presente
        if yaml_content.startswith("```yaml"):
            yaml_content = yaml_content.split("```yaml").split("```").strip()
        elif yaml_content.startswith("```"):
            yaml_content = yaml_content.split("```")
        
        return yaml_content
    
    def _validate_yaml(self, yaml_content: str):
        """Valida estrutura do YAML."""
        try:
            data = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML generated: {e}")
        
        # Valida campos obrigatórios
        required_fields = ['name', 'framework', 'rules']
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")
        
        # Valida estrutura de regras
        if not isinstance(data['rules'], list):
            raise ValueError("'rules' must be a list")
        
        for rule in data['rules']:
            required_rule_fields = ['id', 'action', 'priority']
            for field in required_rule_fields:
                if field not in rule:
                    raise ValueError(f"Rule missing field: {field}")
        
        logger.debug("✅ YAML validation passed")
    
    def save_yaml(self, yaml_content: str, output_path: Path):
        """Salva YAML em arquivo."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(yaml_content)
        
        logger.info(f"✅ Policy saved: {output_path}")

# USAGE EXAMPLE
if __name__ == "__main__":
    translator = ComplianceTranslator(model="gpt-4o")
    
    yaml_policy = translator.translate_pdf(
        pdf_path="docs/LGPD_Art20.pdf",
        framework="LGPD"
    )
    
    translator.save_yaml(yaml_policy, "policies/lgpd_art20.yaml")
    print("✅ Translation complete")
