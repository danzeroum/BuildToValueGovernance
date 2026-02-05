"""
Integration Test - Rust Kernel ↔ Python Governance

Testa:
- FFI bridge funcionando
- scan_for_evidence() end-to-end
- Ledger persistence
- Performance <50ms
"""

import sys
import time
from pathlib import Path

# Import Rust kernel (assume já compilado)
try:
    from buildtovalue_kernel import RustKernel
except ImportError:
    print("❌ Failed to import buildtovalue_kernel")
    print("Build first: cd rust && maturin develop")
    sys.exit(1)


def test_basic_scan():
    """Teste básico de scan."""
    print("[1/5] Testing basic scan...")

    kernel = RustKernel()

    input_text = "Test input with CPF: 123.456.789-00"
    evidence = kernel.scan_for_evidence(input_text)

    # Verifica estrutura
    assert evidence.version == 2, f"Expected version 2, got {evidence.version}"
    assert evidence.timestamp > 0, "Timestamp should be > 0"
    assert evidence.input_size == len(input_text), f"Input size mismatch"

    print(f"  Evidence: {evidence}")
    print(f"  Risk: {evidence.composite_risk:.2f}")
    print(f"  Findings: {evidence.finding_count}")
    print("  ✅ Basic scan OK")


def test_ledger_persistence():
    """Teste de persistência no ledger."""
    print("\n[2/5] Testing ledger persistence...")

    import tempfile
    temp_wal = tempfile.NamedTemporaryFile(delete=False, suffix=".wal")

    kernel = RustKernel(wal_path=temp_wal.name)

    # Scan + persist
    evidence, seq = kernel.scan_and_persist("Sensitive data test")

    assert seq == 0, f"First seq should be 0, got {seq}"

    # Segundo scan
    evidence2, seq2 = kernel.scan_and_persist("Another test")
    assert seq2 == 1, f"Second seq should be 1, got {seq2}"

    print(f"  Seq 1: {seq}")
    print(f"  Seq 2: {seq2}")
    print("  ✅ Ledger persistence OK")


def test_hash_integrity():
    """Teste de integridade via hash."""
    print("\n[3/5] Testing hash integrity...")

    kernel = RustKernel()
    evidence = kernel.scan_for_evidence("Hash test input")

    # Hash deve validar
    assert evidence.validate_hash(), "Hash validation failed"

    print(f"  Hash: {evidence.hash()[:16]}...")
    print("  ✅ Hash integrity OK")


def test_performance():
    """Teste de performance (<50ms end-to-end)."""
    print("\n[4/5] Testing performance (<50ms)...")

    kernel = RustKernel()

    # Warmup
    for _ in range(10):
        kernel.scan_for_evidence("warmup")

    # Benchmark
    iterations = 100
    start = time.perf_counter()

    for _ in range(iterations):
        kernel.scan_for_evidence("Performance test input with patterns")

    elapsed_ms = (time.perf_counter() - start) * 1000
    avg_ms = elapsed_ms / iterations

    print(f"  Total: {elapsed_ms:.2f}ms")
    print(f"  Avg: {avg_ms:.2f}ms")

    # SLA: <50ms
    assert avg_ms < 50, f"Avg latency {avg_ms:.2f}ms exceeds 50ms SLA"

    print("  ✅ Performance OK (<50ms)")


def test_metrics():
    """Teste de métricas."""
    print("\n[5/5] Testing metrics...")

    kernel = RustKernel()

    # Executa alguns scans
    for i in range(5):
        kernel.scan_for_evidence(f"Test input {i}")

    # Métricas do gatekeeper
    gk_metrics = kernel.get_gatekeeper_metrics()
    assert gk_metrics['scans_total'] == 5

    print(f"  Scans: {gk_metrics['scans_total']}")
    print(f"  Findings: {gk_metrics['findings_total']}")
    print(f"  Avg latency: {gk_metrics['avg_latency_ms']:.2f}ms")

    print("  ✅ Metrics OK")


def main():
    print("=" * 70)
    print("🔐 INTEGRATION TEST: RUST KERNEL ↔ PYTHON")
    print("=" * 70)
    print()

    try:
        test_basic_scan()
        test_ledger_persistence()
        test_hash_integrity()
        test_performance()
        test_metrics()

        print()
        print("=" * 70)
        print("✅ ALL TESTS PASSED")
        print("=" * 70)
        print()
        print("Rust Kernel ↔ Python integration is PRODUCTION-READY!")
        print()

        return 0

    except AssertionError as e:
        print()
        print("=" * 70)
        print(f"❌ TEST FAILED: {e}")
        print("=" * 70)
        return 1
    except Exception as e:
        print()
        print("=" * 70)
        print(f"❌ ERROR: {e}")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
