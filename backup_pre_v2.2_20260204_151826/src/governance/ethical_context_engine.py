
class EthicalContextEngine:
    def _apply_rules(
        self,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        profile: Profile,
        risk_level: str,
    ) -> tuple[ActionType, Optional[Rule]]:
        """
        Aplica regras do perfil (ordem de prioridade).
        
        Retorna: (ActionType, matched_rule)
        """
        
        # Itera por prioridade (decrescente)
        for rule in profile.rules:
            if self._rule_matches(rule, evidence, context, risk_level):
                action = ActionType[rule.action]
                
                logger.info(
                    f"Rule matched: {rule.id} → {action.name} "
                    f"(priority: {rule.priority})"
                )
                
                return action, rule
        
        # Sem match → ALLOW (fail-open apenas se ZERO findings)
        if evidence.finding_count + evidence.critical_count == 0:
            return ActionType.ALLOW, None
        else:
            # Findings detectados mas nenhuma regra matchou → LOG
            logger.warning(
                f"Findings detected but no rule matched: "
                f"{[f.title for f in evidence.findings[:3]]}"
            )
            return ActionType.LOG, None
    
    def _rule_matches(
        self,
        rule: Rule,
        evidence: TechnicalEvidence,
        context: RequestMetadata,
        risk_level: str,
    ) -> bool:
        """
        Verifica se regra matcha evidência + contexto.
        
        Condições avaliadas:
        - domain
        - min_risk_level
        - required_findings
        - min_trust_score / max_trust_score
        - condition (DSL simples)
        """
        
        # Condição 1: Domínio
        if rule.domain and context.domain != rule.domain:
            return False
        
        # Condição 2: Risk level
        if rule.min_risk_level:
            risk_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if risk_levels.index(risk_level) < risk_levels.index(rule.min_risk_level):
                return False
        
        # Condição 3: Findings requeridos
        if rule.required_findings:
            evidence_titles = {
                f.title for f in (evidence.findings + evidence.critical)
            }
            
            # Pelo menos 1 finding requerido deve estar presente
            if not any(req in evidence_titles for req in rule.required_findings):
                return False
        
        # Condição 4: Trust score
        trust_score = self.trust_calculator.calculate(
            context.session_id, context.user_role
        )
        
        if rule.min_trust_score and trust_score < rule.min_trust_score:
            return False
        
        if rule.max_trust_score and trust_score > rule.max_trust_score:
            return False
        
        # Condição 5: Expressão customizada (DSL)
        if rule.condition:
            # Cria contexto de avaliação
            eval_context = {
                'finding': evidence,
                'context': context,
                'stats': evidence.stats,
                'risk_level': risk_level,
                'trust_score': trust_score,
                # Helpers
                'has_cpf': any(f.title == 'CPF_PATTERN_DETECTED' for f in evidence.findings + evidence.critical),
                'has_cnpj': any(f.title == 'CNPJ_PATTERN_DETECTED' for f in evidence.findings + evidence.critical),
                'has_credit_card': any(f.title == 'CREDIT_CARD_DETECTED' for f in evidence.findings + evidence.critical),
                'count': lambda items: len(items),
            }
            
            try:
                # Avalia expressão (sandboxed)
                result = self._safe_eval(rule.condition, eval_context)
                if not result:
                    return False
            except Exception as e:
                logger.error(f"Rule condition failed: {rule.id} - {e}")
                return False
        
        # Todas as condições passaram
        return True
    
    def _safe_eval(self, expression: str, context: dict) -> bool:
        """
        Avalia expressão de forma segura (sandbox).
        
        Permite apenas:
        - Operadores: ==, !=, >, <, >=, <=, AND, OR, NOT
        - Acesso a variáveis do context
        - Funções whitelist (count, len, any, all)
        """
        
        # TODO: Implementar parser seguro (não usar eval() direto!)
        # Opções:
        # 1. Parser customizado (AST)
        # 2. Biblioteca: pyparsing, lark
        # 3. CEL (Common Expression Language)
        
        # Por ora, validação simples:
        forbidden = ['import', 'exec', 'eval', '__', 'open', 'file']
        if any(word in expression.lower() for word in forbidden):
            raise ValueError(f"Forbidden expression: {expression}")
        
        # Avalia (em produção, usar parser seguro!)
        return eval(expression, {"__builtins__": {}}, context)