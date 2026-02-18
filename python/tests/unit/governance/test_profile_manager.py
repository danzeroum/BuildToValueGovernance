"""
Testes para ProfileManager v2.0.

Coverage: Herança, Override, Merge.
"""

import pytest
from pathlib import Path
from buildtovalue.governance.profile_manager import ProfileManager, Profile, PolicyRule


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def profiles_dir(tmp_path):
    """Cria diretório temporário com profiles de teste."""
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()

    # Base profile
    base_yaml = profiles_dir / "base.yaml"
    base_yaml.write_text("""
id: base
name: Base Profile
description: Base profile
parent_id: null
version: 1.0.0
created_at: 2026-02-16
updated_at: 2026-02-16
rules:
  - id: RULE_A
    name: Rule A
    description: Rule from base
    action: BLOCK
    priority: 100
  - id: RULE_B
    name: Rule B
    description: Another rule from base
    action: LOG
    priority: 50
domain_config:
  general:
    risk_multiplier: 1.0
    education_message: Base message
""")

    # Medical profile (inherits from base)
    medical_yaml = profiles_dir / "medical.yaml"
    medical_yaml.write_text("""
id: medical
name: Medical Profile
description: Medical profile
parent_id: base
version: 1.0.0
created_at: 2026-02-16
updated_at: 2026-02-16
rules:
  - id: RULE_A
    name: Rule A Override
    description: Override from medical
    action: EDUCATE
    priority: 100
  - id: RULE_C
    name: Rule C
    description: New rule from medical
    action: LOG
    priority: 80
domain_config:
  medical:
    risk_multiplier: 0.7
    education_message: Medical message
""")

    return profiles_dir


@pytest.fixture
def manager(profiles_dir):
    """ProfileManager para testes."""
    return ProfileManager(profiles_dir)


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE LOAD
# ═══════════════════════════════════════════════════════════════════════════

class TestProfileLoad:
    """Testes de carregamento de perfis."""

    def test_load_base_profile(self, manager):
        """Deve carregar perfil base."""
        profile = manager.load_profile("base")

        assert profile.id == "base"
        assert profile.name == "Base Profile"
        assert profile.parent_id is None
        assert len(profile.rules) == 2

    def test_load_nonexistent_profile(self, manager):
        """Deve falhar se perfil não existe."""
        with pytest.raises(ValueError, match="Profile not found"):
            manager.load_profile("nonexistent")

    def test_cache_hit(self, manager):
        """Deve usar cache no segundo load."""
        profile1 = manager.load_profile("base")
        profile2 = manager.load_profile("base")

        # Same object (cached)
        assert profile1 is profile2

        metrics = manager.get_metrics()
        assert metrics['cache_hits'] == 1
        assert metrics['cache_misses'] == 1


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE HERANÇA
# ═══════════════════════════════════════════════════════════════════════════

class TestInheritance:
    """Testes de herança hierárquica."""

    def test_inherit_rules(self, manager):
        """Deve herdar regras do pai."""
        medical = manager.load_profile("medical")

        # Medical tem 3 regras: RULE_A (override), RULE_B (herdada), RULE_C (própria)
        assert len(medical.rules) == 3

        rule_ids = [r.id for r in medical.rules]
        assert "RULE_A" in rule_ids
        assert "RULE_B" in rule_ids
        assert "RULE_C" in rule_ids

    def test_override_rule(self, manager):
        """Filho deve sobrescrever regra do pai (mesmo ID)."""
        medical = manager.load_profile("medical")

        # RULE_A foi overridden
        rule_a = next(r for r in medical.rules if r.id == "RULE_A")
        assert rule_a.action == "EDUCATE"  # Medical override (base era BLOCK)
        assert "Override" in rule_a.name

    def test_rules_sorted_by_priority(self, manager):
        """Regras devem estar ordenadas por prioridade."""
        medical = manager.load_profile("medical")

        priorities = [r.priority for r in medical.rules]
        assert priorities == sorted(priorities, reverse=True)

    def test_domain_config_merge(self, manager):
        """Deve fazer merge de domain configs."""
        medical = manager.load_profile("medical")

        # Medical tem config próprio
        assert "medical" in medical.domain_config
        assert medical.domain_config["medical"].risk_multiplier == 0.7

        # Medical herdou config do base
        assert "general" in medical.domain_config
        assert medical.domain_config["general"].risk_multiplier == 1.0


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE VALIDAÇÃO
# ═══════════════════════════════════════════════════════════════════════════

class TestValidation:
    """Testes de validação."""

    def test_circular_inheritance(self, tmp_path):
        """Deve detectar herança circular."""
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir()

        # A → B → A (circular!)
        (profiles_dir / "a.yaml").write_text("""
id: a
name: A
description: A
parent_id: b
rules: []
""")

        (profiles_dir / "b.yaml").write_text("""
id: b
name: B
description: B
parent_id: a
rules: []
""")

        manager = ProfileManager(profiles_dir)

        with pytest.raises(ValueError, match="Circular inheritance"):
            manager.load_profile("a")


# ═══════════════════════════════════════════════════════════════════════════
# TESTES DE PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════════

class TestPerformance:
    """Testes de performance."""

    def test_load_latency(self, manager):
        """Load deve ser <5ms (cached)."""
        import time

        # First load (miss)
        start = time.perf_counter()
        manager.load_profile("base")
        first_load_ms = (time.perf_counter() - start) * 1000

        print(f"\nFirst load: {first_load_ms:.2f}ms")

        # Second load (hit)
        start = time.perf_counter()
        manager.load_profile("base")
        cached_load_ms = (time.perf_counter() - start) * 1000

        print(f"Cached load: {cached_load_ms:.2f}ms")

        # Cached deve ser muito rápido
        assert cached_load_ms < 1.0, f"Cached load {cached_load_ms:.2f}ms too slow"


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
