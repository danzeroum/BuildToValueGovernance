
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_concurrent_evidence_creation() {
    let num_threads = 16;
    let iterations_per_thread = 1000;
    
    let mut handles = vec![];
    
    for thread_id in 0..num_threads {
        let handle = thread::spawn(move || {
            for i in 0..iterations_per_thread {
                let mut evidence = TechnicalEvidence::new((thread_id * 1000 + i) as u64);
                
                // Adiciona findings
                for j in 0..5 {
                    evidence.add_finding(create_test_finding(j));
                }
                
                // Finaliza
                evidence.finalize().unwrap();
                
                // Valida
                assert!(evidence.validate());
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    println!("\n✅ Concurrent evidence creation: {} threads × {} iterations", 
             num_threads, iterations_per_thread);
}

#[test]
fn test_concurrent_ledger_writes() {
    use buildtovalue::kernel::ledger::DurableLedger;
    use std::path::PathBuf;
    
    let ledger = Arc::new(DurableLedger::new(
        PathBuf::from("/tmp/stress_test_ledger.dat")
    ).unwrap());
    
    let num_threads = 8;
    let writes_per_thread = 500;
    
    let mut handles = vec![];
    
    for thread_id in 0..num_threads {
        let ledger_clone = Arc::clone(&ledger);
        
        let handle = thread::spawn(move || {
            for i in 0..writes_per_thread {
                let evidence = TechnicalEvidence::new((thread_id * 1000 + i) as u64);
                let verdict = create_mock_verdict();
                let entry = LedgerEntry::new(
                    thread_id * 1000 + i,
                    evidence.audit_trail_id,
                    &evidence,
                    &verdict,
                    0,
                );
                
                ledger_clone.append(entry).unwrap();
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    println!("\n✅ Concurrent ledger writes: {} threads × {} writes", 
             num_threads, writes_per_thread);
}

#[test]
fn test_sustained_load() {
    let kernel = Arc::new(RustSovereignKernel::new());
    let duration = Duration::from_secs(30);
    
    println!("\n🔥 Sustained load test (30 seconds)...");
    
    let start = Instant::now();
    let request_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    
    let mut handles = vec![];
    
    for _ in 0..8 {
        let kernel_clone = Arc::clone(&kernel);
        let count_clone = Arc::clone(&request_count);
        
        let handle = thread::spawn(move || {
            while start.elapsed() < duration {
                let input = "CPF: 123.456.789-09";
                let _ = kernel_clone.scan_for_evidence(input);
                
                count_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        });
        
        handles.push(handle);
    }
    
    // Monitor progress
    for i in 0..30 {
        thread::sleep(Duration::from_secs(1));
        let current_count = request_count.load(std::sync::atomic::Ordering::Relaxed);
        print!(".");
        std::io::stdout().flush().unwrap();
        
        if (i + 1) % 10 == 0 {
            println!(" {}s: {} req", i + 1, current_count);
        }
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let total = request_count.load(std::sync::atomic::Ordering::Relaxed);
    let throughput = total as f64 / 30.0;
    
    println!("\n✅ Sustained load completed:");
    println!("   Total requests: {}", total);
    println!("   Throughput: {:.0} req/s", throughput);
}