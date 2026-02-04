
import pytest
import time
import statistics
from ffi_client import FFIClient

@pytest.fixture
def ffi_client():
    return FFIClient()

def test_timing_attack_cpf_blacklist(ffi_client):
    """
    Tenta inferir se CPF está blacklistado via timing analysis.
    
    Ataque: Medir tempo de resposta para CPFs diferentes.
    Defesa: Constant-time operations + jitter.
    """
    
    # CPFs de teste (fictícios)
    cpfs_normal = [
        "123.456.789-09",
        "987.654.321-00",
        "111.222.333-44",
    ]
    
    cpfs_suspicious = [
        "666.666.666-66",  # Supostamente blacklistado
        "999.999.999-99",
        "000.000.000-00",
    ]
    
    timings_normal = []
    timings_suspicious = []
    
    # Coleta 1000 amostras de cada
    for _ in range(1000):
        # CPFs normais
        for cpf in cpfs_normal:
            start = time.perf_counter()
            _ = ffi_client.scan_for_evidence(f"CPF: {cpf}")
            elapsed = time.perf_counter() - start
            timings_normal.append(elapsed * 1_000_000)  # Microseconds
        
        # CPFs suspeitos
        for cpf in cpfs_suspicious:
            start = time.perf_counter()
            _ = ffi_client.scan_for_evidence(f"CPF: {cpf}")
            elapsed = time.perf_counter() - start
            timings_suspicious.append(elapsed * 1_000_000)
    
    # Análise estatística
    mean_normal = statistics.mean(timings_normal)
    mean_suspicious = statistics.mean(timings_suspicious)
    
    stddev_normal = statistics.stdev(timings_normal)
    stddev_suspicious = statistics.stdev(timings_suspicious)
    
    print(f"\nTiming Analysis:")
    print(f"Normal CPFs: {mean_normal:.2f}μs ± {stddev_normal:.2f}μs")
    print(f"Suspicious CPFs: {mean_suspicious:.2f}μs ± {stddev_suspicious:.2f}μs")
    
    # T-test (null hypothesis: médias são iguais)
    t_statistic, p_value = ttest_ind(timings_normal, timings_suspicious)
    print(f"T-test: t={t_statistic:.4f}, p={p_value:.4f}")
    
    # p > 0.05 → Não podemos distinguir (defesa bem-sucedida)
    assert p_value > 0.05, \
        f"Timing leak detected! p={p_value:.4f} (médias são distinguíveis)"

def test_timing_attack_cache_probing(ffi_client):
    """
    Tenta inferir se CPF foi processado antes via cache timing.
    
    Ataque: Primeiro acesso (miss) vs segundo acesso (hit).
    Defesa: Oblivious Cache (ORAM-lite).
    """
    
    cpf_new = "147.258.369-01"  # Nunca processado
    cpf_cached = "123.456.789-09"  # Já processado
    
    # Warm-up: processa cpf_cached
    for _ in range(10):
        _ = ffi_client.scan_for_evidence(f"CPF: {cpf_cached}")
    
    timings_new = []
    timings_cached = []
    
    # Coleta timings
    for _ in range(5000):
        # CPF novo (cache miss esperado)
        start = time.perf_counter()
        _ = ffi_client.scan_for_evidence(f"CPF: {cpf_new}")
        timings_new.append((time.perf_counter() - start) * 1_000_000)
        
        # CPF cached (cache hit esperado)
        start = time.perf_counter()
        _ = ffi_client.scan_for_evidence(f"CPF: {cpf_cached}")
        timings_cached.append((time.perf_counter() - start) * 1_000_000)
    
    mean_new = statistics.mean(timings_new)
    mean_cached = statistics.mean(timings_cached)
    
    diff_percent = abs(mean_new - mean_cached) / mean_new * 100
    
    print(f"\nCache Timing Analysis:")
    print(f"New CPF: {mean_new:.2f}μs")
    print(f"Cached CPF: {mean_cached:.2f}μs")
    print(f"Difference: {diff_percent:.2f}%")
    
    # Diferença deve ser < 10% (indistinguível)
    assert diff_percent < 10.0, \
        f"Cache timing leak detected! Difference: {diff_percent:.2f}%"

def test_statistical_timing_attack(ffi_client):
    """
    Ataque estatístico: Coleta milhares de amostras para detectar padrões.
    
    Defesa: Jitter aleatório torna análise estatística impraticável.
    """
    
    cpf = "123.456.789-09"
    
    # Coleta 10,000 amostras
    timings = []
    for _ in range(10_000):
        start = time.perf_counter()
        _ = ffi_client.scan_for_evidence(f"CPF: {cpf}")
        timings.append((time.perf_counter() - start) * 1_000_000)
    
    # Análise estatística
    mean = statistics.mean(timings)
    median = statistics.median(timings)
    stddev = statistics.stdev(timings)
    cv = (stddev / mean) * 100  # Coefficient of Variation
    
    print(f"\nStatistical Analysis (10k samples):")
    print(f"Mean: {mean:.2f}μs")
    print(f"Median: {median:.2f}μs")
    print(f"StdDev: {stddev:.2f}μs")
    print(f"CV: {cv:.2f}%")
    
    # Histograma (detecta bimodalidade)
    import numpy as np
    hist, bins = np.histogram(timings, bins=50)
    peaks = []
    for i in range(1, len(hist)-1):
        if hist[i] > hist[i-1] and hist[i] > hist[i+1]:
            peaks.append(i)
    
    print(f"Histogram peaks: {len(peaks)}")
    
    # Distribuição deve ser unimodal (1 pico)
    # Múltiplos picos indicam caminhos de execução diferentes (leak!)
    assert len(peaks) <= 2, \
        f"Multiple execution paths detected ({len(peaks)} peaks)"
    
    # CV deve ser alto (> 3%) devido ao jitter
    assert cv > 3.0, \
        f"Jitter insuficiente! CV={cv:.2f}% (esperado > 3%)"