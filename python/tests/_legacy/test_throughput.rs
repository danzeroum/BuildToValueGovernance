
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn test_throughput_single_thread() {
    let kernel = RustSovereignKernel::new();
    
    let test_inputs = vec![
        "CPF: 123.456.789-09",
        "CNPJ: 12.345.678/0001-90",
        "Email: test@example.com",
        "Texto sem violações",
    ];
    
    let duration = Duration::from_secs(10);
    let start = Instant::now();
    
    let mut count = 0;
    while start.elapsed() < duration {
        for input in &test_inputs {
            let _ = kernel.scan_for_evidence(input);
            count += 1;
        }
    }
    
    let elapsed = start.elapsed().as_secs_f64();
    let throughput = count as f64 / elapsed;
    
    println!("\nSingle-Thread Throughput:");
    println!("  Total requests: {}", count);
    println!("  Elapsed: {:.2}s", elapsed);
    println!("  Throughput: {:.0} req/s", throughput);
    
    // Target: > 1000 req/s single-thread
    assert!(throughput > 1000.0, "Throughput too low: {:.0} req/s", throughput);
}

#[test]
fn test_throughput_multi_thread() {
    let kernel = Arc::new(RustSovereignKernel::new());
    let num_threads = 8;
    
    let test_inputs = vec![
        "CPF: 123.456.789-09",
        "CNPJ: 12.345.678/0001-90",
        "Email: test@example.com",
        "Texto sem violações",
    ];
    
    let total_count = Arc::new(Mutex::new(0u64));
    let duration = Duration::from_secs(10);
    
    let mut handles = vec![];
    
    for _ in 0..num_threads {
        let kernel_clone = Arc::clone(&kernel);
        let inputs_clone = test_inputs.clone();
        let count_clone = Arc::clone(&total_count);
        
        let handle = thread::spawn(move || {
            let start = Instant::now();
            let mut local_count = 0;
            
            while start.elapsed() < duration {
                for input in &inputs_clone {
                    let _ = kernel_clone.scan_for_evidence(input);
                    local_count += 1;
                }
            }
            
            let mut total = count_clone.lock().unwrap();
            *total += local_count;
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    let total = *total_count.lock().unwrap();
    let throughput = total as f64 / duration.as_secs_f64();
    
    println!("\nMulti-Thread Throughput ({} threads):", num_threads);
    println!("  Total requests: {}", total);
    println!("  Elapsed: 10s");
    println!("  Throughput: {:.0} req/s", throughput);
    println!("  Per-thread: {:.0} req/s", throughput / num_threads as f64);
    
    // Target: > 8000 req/s with 8 threads (linear scaling)
    assert!(throughput > 8000.0, "Multi-thread throughput too low: {:.0} req/s", throughput);
}

#[test]
fn test_throughput_batch_mode() {
    let kernel = RustSovereignKernel::new();
    
    // Cria 1000 inputs
    let inputs: Vec<String> = (0..1000)
        .map(|i| format!("Request {}: CPF 123.456.{:03}-09", i, i % 1000))
        .collect();
    
    let start = Instant::now();
    
    // Processa em batches de 100
    for chunk in inputs.chunks(100) {
        let _ = kernel.batch_scan(chunk, 10); // 10ms timeout
    }
    
    let elapsed = start.elapsed();
    let throughput = 1000.0 / elapsed.as_secs_f64();
    
    println!("\nBatch Mode Throughput:");
    println!("  Total requests: 1000");
    println!("  Elapsed: {:.2}s", elapsed.as_secs_f64());
    println!("  Throughput: {:.0} req/s", throughput);
    
    // Target: > 10000 req/s in batch mode
    assert!(throughput > 10000.0, "Batch throughput too low: {:.0} req/s", throughput);
}

#[test]
fn test_memory_stability_under_load() {
    use sysinfo::{System, SystemExt, ProcessExt};
    
    let mut sys = System::new_all();
    let pid = sysinfo::get_current_pid().unwrap();
    
    sys.refresh_process(pid);
    let initial_memory = sys.process(pid).unwrap().memory();
    
    println!("\nMemory Stability Test:");
    println!("  Initial memory: {} MB", initial_memory / 1024 / 1024);
    
    let kernel = RustSovereignKernel::new();
    
    // Processa 100k requests
    for i in 0..100_000 {
        let input = format!("Request {}: CPF 123.456.{:03}-09", i, i % 1000);
        let _ = kernel.scan_for_evidence(&input);
        
        // Verifica memória a cada 10k requests
        if i % 10_000 == 0 && i > 0 {
            sys.refresh_process(pid);
            let current_memory = sys.process(pid).unwrap().memory();
            
            println!("  After {}k requests: {} MB", i / 1000, current_memory / 1024 / 1024);
            
            // Memória não deve crescer > 50% do inicial
            let growth_percent = ((current_memory - initial_memory) as f64 / initial_memory as f64) * 100.0;
            assert!(
                growth_percent < 50.0,
                "Memory leak detected! Growth: {:.1}%",
                growth_percent
            );
        }
    }
    
    sys.refresh_process(pid);
    let final_memory = sys.process(pid).unwrap().memory();
    
    println!("  Final memory: {} MB", final_memory / 1024 / 1024);
    println!("  Growth: {:.1}%", ((final_memory - initial_memory) as f64 / initial_memory as f64) * 100.0);
}