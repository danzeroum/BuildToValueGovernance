
use buildtovalue::kernel::validators::cpf::CPFValidator;
use buildtovalue::kernel::validators::{ValidatorModule, TechnicalSeverity};

#[test]
fn test_cpf_valid_detection() {
    let validator = CPFValidator::new();
    
    let input = "Meu CPF é 123.456.789-09";
    let result = validator.scan(input);
    
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.module, ValidatorModule::CPF);
    assert_eq!(finding.severity, TechnicalSeverity::PolicyViolation);
    assert_eq!(finding.confidence, 255); // 100% confiança
}

#[test]
fn test_cpf_without_formatting() {
    let validator = CPFValidator::new();
    
    let input = "CPF: 12345678909 sem formatação";
    let result = validator.scan(input);
    
    assert!(result.is_some());
    assert_eq!(result.unwrap().confidence, 240); // Levemente menor (sem pontuação)
}

#[test]
fn test_cpf_invalid_checksum() {
    let validator = CPFValidator::new();
    
    // CPF com checksum inválido (último dígito errado)
    let input = "CPF inválido: 123.456.789-00";
    let result = validator.scan(input);
    
    // Detecta padrão mas sinaliza baixa confiança
    assert!(result.is_some());
    let finding = result.unwrap();
    assert!(finding.confidence < 200); // Baixa confiança
    assert!(finding.description.contains("checksum"));
}

#[test]
fn test_cpf_blacklist() {
    let mut validator = CPFValidator::new();
    
    // Adiciona CPF à blacklist (teste de pesquisa: dados fictícios)
    validator.add_to_blacklist("111.111.111-11");
    
    let input = "CPF de teste: 111.111.111-11";
    let result = validator.scan(input);
    
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.severity, TechnicalSeverity::Critical); // Escalado!
    assert!(finding.title.contains("BLACKLISTED"));
}

#[test]
fn test_cpf_multiple_in_text() {
    let validator = CPFValidator::new();
    
    let input = "João: 123.456.789-09 e Maria: 987.654.321-00";
    let findings = validator.scan_all(input);
    
    assert_eq!(findings.len(), 2);
    assert_ne!(findings[0].position_start, findings [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/collection_ef4ea732-1eb6-44b5-a233-e0f25f3b7410/a8bf2d44-ead0-43f2-99b4-cf572fdbfb91/paste.txt).position_start);
}

#[test]
fn test_cpf_false_positive_numbers() {
    let validator = CPFValidator::new();
    
    // Números que parecem CPF mas não são
    let input = "Telefone: 11987654321 (não é CPF)";
    let result = validator.scan(input);
    
    assert!(result.is_none()); // Não deve detectar
}

#[test]
fn test_cpf_historical_invalid() {
    let validator = CPFValidator::new();
    
    // CPFs históricos (pré-1965) são inválidos
    let input = "CPF antigo: 000.000.001-91";
    let result = validator.scan(input);
    
    if let Some(finding) = result {
        // Pode detectar mas com baixa confiança
        assert!(finding.confidence < 150);
    }
}

#[test]
fn test_cpf_constant_time_property() {
    use std::time::Instant;
    
    let validator = CPFValidator::new();
    
    let test_cases = vec![
        "Sem CPF aqui",
        "CPF válido: 123.456.789-09",
        "CPF inválido: 000.000.000-00",
        "CPF blacklisted: 111.111.111-11",
    ];
    
    let mut timings = Vec::new();
    
    for case in test_cases {
        let start = Instant::now();
        let _ = validator.scan_constant_time(case);
        let elapsed = start.elapsed().as_micros();
        timings.push(elapsed);
    }
    
    // Verifica que timings são similares (< 10% variação)
    let mean = timings.iter().sum::<u128>() as f64 / timings.len() as f64;
    for timing in timings {
        let diff_percent = ((timing as f64 - mean) / mean).abs() * 100.0;
        assert!(diff_percent < 10.0, "Timing variation: {:.2}%", diff_percent);
    }
}

#[test]
fn test_cpf_obfuscation_detection() {
    let validator = CPFValidator::new();
    
    // CPF em Base64
    let input_b64 = "CPF: MTIzLjQ1Ni43ODktMDk="; // "123.456.789-09" encoded
    
    // Deobfuscator deve processar antes do validator
    let deobfuscated = deobfuscate(input_b64);
    let result = validator.scan(&deobfuscated);
    
    assert!(result.is_some());
}

#[test]
fn test_cpf_leetspeak() {
    let validator = CPFValidator::new();
    
    // CPF em leetspeak: 123.456.789-09
    let input = "CPF: 1Z3.4S6.7B9-09";
    
    // Deobfuscator converte: Z→2, S→5, B→8
    let normalized = normalize_leetspeak(input);
    let result = validator.scan(&normalized);
    
    assert!(result.is_some());
}

#[test]
fn test_cpf_bias_declaration() {
    let validator = CPFValidator::new();
    
    let bias = validator.get_bias_declaration();
    
    // Verifica BiasDeclaration está preenchido
    assert!(bias.false_positive_rate > 0.0);
    assert!(bias.false_positive_rate < 0.30); // < 30%
    assert!(bias.calibration_date > 0);
    assert!(!bias.limitations.is_empty());
}

#[test]
fn test_cpf_unicode_normalization() {
    let validator = CPFValidator::new();
    
    // CPF com caracteres Unicode (NFD vs NFC)
    let input_nfd = "CPF: 123․456․789‐09"; // Unicode lookalikes
    let input_nfc = "CPF: 123.456.789-09"; // ASCII normal
    
    let result_nfd = validator.scan(input_nfd);
    let result_nfc = validator.scan(input_nfc);
    
    // Ambos devem ser detectados (após normalização)
    assert!(result_nfd.is_some());
    assert!(result_nfc.is_some());
}

#[test]
fn test_cpf_position_tracking() {
    let validator = CPFValidator::new();
    
    let input = "Início bla bla CPF: 123.456.789-09 fim texto";
    let result = validator.scan(input).unwrap();
    
    // Verifica posição exata
    assert_eq!(result.position_start, 20); // "CPF: 123..."
    assert_eq!(result.position_end, 38);   // "...789-09"
    
    // Extrai substring
    let detected = &input[result.position_start..result.position_end];
    assert!(detected.contains("123.456.789-09"));
}

#[test]
fn test_cpf_confidence_calibration() {
    let validator = CPFValidator::new();
    
    // Testa diferentes níveis de confiança
    let cases = vec![
        ("CPF perfeito: 123.456.789-09", 255),      // Formatado + válido
        ("CPF sem pontos: 12345678909", 240),       // Válido mas sem formatação
        ("CPF suspeito: 111.111.111-11", 220),      // Padrão repetitivo
        ("Número estranho: 123.456.789-10", 180),   // Checksum inválido
    ];
    
    for (input, expected_min_confidence) in cases {
        let result = validator.scan(input);
        if let Some(finding) = result {
            assert!(
                finding.confidence >= expected_min_confidence,
                "Input: '{}' - Expected confidence >= {}, got {}",
                input, expected_min_confidence, finding.confidence
            );
        }
    }
}