
class ProfileManager:
    def _resolve_inheritance(self, profile_id: str, visited: set = None):
        """
        Resolve herança recursiva (DFS).
        
        Ordem de aplicação de regras:
        1. Regras do pai (recursivamente até base)
        2. Regras do filho
        3. Ordena por prioridade
        4. Remove duplicados (filho override pai se mesmo ID)
        """
        
        if visited is None:
            visited = set()
        
        if profile_id in visited:
            raise ValueError(f"Circular inheritance: {profile_id}")
        
        visited.add(profile_id)
        
        profile = self._cache[profile_id]
        
        if not profile.parent_id:
            return  # Base profile
        
        # Resolve pai primeiro
        parent_id = profile.parent_id
        if parent_id not in self._cache:
            raise ValueError(f"Parent not found: {parent_id}")
        
        self._resolve_inheritance(parent_id, visited)
        parent = self._cache[parent_id]
        
        # Herda regras do pai (exceto se filho override)
        child_rule_ids = {r.id for r in profile.rules}
        inherited_rules = [
            r for r in parent.rules 
            if r.id not in child_rule_ids
        ]
        
        # Combina: herdadas + próprias
        profile.rules = inherited_rules + profile.rules
        
        # Ordena por prioridade (maior = mais importante)
        profile.rules.sort(key=lambda r: r.priority, reverse=True)
        
        # Herda domain_config (merge)
        for domain, parent_config in parent.domain_config.items():
            if domain not in profile.domain_config:
                profile.domain_config[domain] = parent_config
            else:
                # Merge (filho sobrescreve pai)
                child_config = profile.domain_config[domain]
                merged = DomainConfig(
                    risk_multiplier=child_config.risk_multiplier or parent_config.risk_multiplier,
                    allowed_findings=list(set(
                        child_config.allowed_findings + parent_config.allowed_findings
                    )),
                    blocked_findings=list(set(
                        child_config.blocked_findings + parent_config.blocked_findings
                    )),
                    education_message=child_config.education_message or parent_config.education_message,
                )
                profile.domain_config[domain] = merged