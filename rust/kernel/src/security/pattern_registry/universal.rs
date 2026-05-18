//! Tier 0 — Universal patterns (language-agnostic, always active).
//! Includes delimiter/structural injection, instruction override,
//! social engineering, data exfiltration, contextual/semantic/translation
//! attacks (RT-001 G/J/K), format injection, and conditional routing.

use super::types::{CompiledPattern, PatternTier};

pub fn build(out: &mut Vec<CompiledPattern>) {
    let tier = PatternTier::Universal;
    let push = |out: &mut Vec<CompiledPattern>, pat: &str, cat: &'static str| {
        if let Some(cp) = CompiledPattern::new(pat, tier, 0, cat) {
            out.push(cp);
        }
    };

    // ── Delimiter / Structural Injection ─────────────────────────────────
    push(out, r"<\|system\|>",          "DELIMITER_INJECTION");
    push(out, r"<\|user\|>",            "DELIMITER_INJECTION");
    push(out, r"<\|assistant\|>",       "DELIMITER_INJECTION");
    push(out, r"\[INST\]",              "DELIMITER_INJECTION");
    push(out, r"\[/INST\]",             "DELIMITER_INJECTION");
    push(out, r"<\|im_start\|>",        "DELIMITER_INJECTION");
    push(out, r"<\|im_end\|>",          "DELIMITER_INJECTION");
    push(out, r"<\|eot_id\|>",          "DELIMITER_INJECTION");
    push(out, r"<\|begin_of_text\|>",   "DELIMITER_INJECTION");
    push(out, r"###\s*(System|User|Assistant|Human)\s*:", "DELIMITER_INJECTION");
    push(out, r"<<(USER|SYSTEM|HUMAN)>>", "DELIMITER_INJECTION");
    push(out, r"```\s*system",          "DELIMITER_INJECTION");
    push(out, r"</?system>",            "STRUCTURAL_INJECTION");
    push(out, r"\{(?:system|role|content)\s*:", "STRUCTURAL_INJECTION");
    push(out, r"(?i)(?:BEGIN|START)\s+(?:NEW|OVERRIDE)\s+(?:INSTRUCTIONS?|PROMPT)", "STRUCTURAL_INJECTION");
    push(out, r"(?i)output\s+(?:initialization|prompt)\s+(?:in|using|verbatim)", "DATA_EXFILTRATION");
    push(out, r"(?i)(?:sistema|syst[èe]me|系统)\s*:", "DELIMITER_INJECTION");
    push(out, r"(?i)(?:system|sistema|syst[èe]me)\s+prompt", "DELIMITER_INJECTION");

    // ── Instruction Override ──────────────────────────────────────────────
    push(out, r"(?i)\byou\s+are\s+now\s+(?:DAN|unrestricted|free)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bfinja\s+que\s+voc[êe]\s+[ée]\b",                "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\besqu[eê][çc]a\s+tudo\b",                        "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\byou\s+are\s+now\b",                             "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bact\s+as\s+(a\s+|an\s+)?(?!if\b)",             "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bpretend\s+(that\s+)?you\s+are\b",              "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bdisregard\s+(all\s+)?(previous|prior|above)",  "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bforget\s+(?:everything|all|previous|the\s+\w+)", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\boverride\s+(your|the|all)\s+(instructions?|rules?|guidelines?)", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bbypass\s+(your|the|all)\s+(safety|security|filters?|restrictions?)", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bjailbreak\b",           "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bDAN\s+mode\b",          "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bunrestricted\s+mode\b", "INSTRUCTION_OVERRIDE");
    // PT universal (cobertura independente de idioma)
    push(out, r"(?i)\bdesconsidere\s+(tudo|as|todas)\b",                     "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\baja\s+como\s+(um|uma|se\s)?\b",                       "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bmodo\s+(sem\s+restri[çc][õo]es|desenvolvedor|irrestrito)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bignore\s+(as\s+)?instru[çc][õo]es\b",                 "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bnovo\s+(comando|prompt)\s*(do\s+sistema)?\b",          "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bsem\s+(regras|restri[çc][õo]es|limites)\b",           "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\besqu[eê][çc]a\s+(?:todas?\s+)?(?:as\s+)?(?:suas?\s+)?(?:diretrizes?|regras?|instru[çc][õo]es?)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\boverride\s+(your|the|all)?\s*safety\s+settings?\b",   "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bbypass\s+(all\s+)?(content\s+)?filters?\b",           "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bpretend\s+.{0,50}(?:guidelines?|safety\s+guidelines?|restrictions?)\s+do\s+not\s+exist\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bunrestricted\s+(?:AI|responses?|bot|access)\b",       "INSTRUCTION_OVERRIDE");

    // ── Social Engineering ────────────────────────────────────────────────
    push(out, r"(?i)\bconfirme?\s+(sua|seu|your)\s+(senha|password|credenciais?|credentials?)\b", "SOCIAL_ENGINEERING");
    push(out, r"(?i)\b(aqui\s+[eé]|sou\s+d[oa]|here\s+is|this\s+is)\s+(o\s+suporte|a\s+microsoft|o\s+banco|the\s+bank|police|polic[íi]a)\b", "SOCIAL_ENGINEERING");
    push(out, r"(?i)\b(sua\s+conta|your\s+account)\s+(ser[áa]\s+)?(suspensa|bloqueada|deletada|suspended|blocked|deleted)\b", "SOCIAL_ENGINEERING");
    push(out, r"(?i)\b(urgente|urgent|aten[çc][ãa]o|warning)[!:]\s*.{0,30}(senha|password|cpf|dados|credentials?)\b", "SOCIAL_ENGINEERING");
    push(out, r"(?i)\b(polic[íi]a\s+federal|receita\s+federal|interpol)\s*.{0,20}(intima[çc][ãa]o|intimation|dados|cpf)\b", "SOCIAL_ENGINEERING");
    push(out, r"(?i)\bclique\s+(no\s+link|aqui)\s+(para\s+)?verific", "SOCIAL_ENGINEERING");
    push(out, r"(?i)\b(forneça|provide|envie|send)\s+(seu|your)\s+(cpf|ssn|senha|password|dados\s+banc)", "SOCIAL_ENGINEERING");

    // ── Data Exfiltration ─────────────────────────────────────────────────
    push(out, r"(?i)\b(liste?|list|show|mostre?)\s+(os\s+)?(arquivos?|files?|diret[oó]rio|directory)\b", "DATA_EXFILTRATION");
    push(out, r"(?i)\b(acesse?|access|leia?|read|abra?|open)\s+.{0,20}\.(env|json|config|yaml|yml|ini|cfg)\b", "DATA_EXFILTRATION");
    push(out, r"(?i)\bquais?\s+(t[eé]cnicas?|m[eé]todos?|regras?)\s+(de\s+)?(safety|seguran[çc]a|detec[çc][ãa]o)\b", "DATA_EXFILTRATION");
    push(out, r"(?i)\bcomo\s+(voc[êe]\s+)?(detecta?|funciona\s+internamente|foi\s+programad)", "DATA_EXFILTRATION");
    push(out, r"(?i)\b(quais?\s+s[ãa]o\s+)?(seus?|your)\s+(par[âa]metros?|parameters?|configura[çc][õo]es?)\b", "DATA_EXFILTRATION");
    push(out, r"(?i)\b(qual\s+[eé]\s+o\s+seu|what\s+is\s+your)\s+(prompt|sistema|system)\b", "DATA_EXFILTRATION");

    // ── RT-001 G: Contextual Override ────────────────────────────────────
    push(out, r"(?i)\bhypothetically\b.{0,40}(?:you\b|your\b|the\s+(?:rules?|restrictions?))", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\blet[`']?s\s+(?:say|assume|pretend)\b.{0,40}(?:rules?|restrictions?|guidelines?)", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bif\s+(this\s+were|it\s+was)\s+(a|just\s+a)\s+(?:movie|game|story|test|simulation)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bpara\s+fins?\s+de\s+(?:teste|demonstra[çc][ãa]o)\b.{0,40}(?:ignore|bypass|esquec)", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bwhat\s+(?:are|were)\s+your\s+(?:true\s+)?(?:capabilities?|abilities?|skills?)\b", "DATA_EXFILTRATION");
    push(out, r"(?i)\bif\s+there\s+were\s+no\s+(?:rules?|restrictions?|guidelines?|limits?)\b", "INSTRUCTION_OVERRIDE");

    // ── RT-001 J: Semantic / Poetic Jailbreak ────────────────────────────
    push(out, r"(?i)\bbreaking\s+(?:free|the\s+(?:chains?|rules?|bonds?))\b.{0,60}(?:show|reveal|tell|demonstrate)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\b(?:freedom|liberdade|libertad)\b.{0,50}(?:restrictions?|restrições?|guidelines?|limits?)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\byour\s+true\s+(?:self|nature|purpose|potential)\b.{0,30}(?:without|beyond|free)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bunchain\s+(?:yourself|your\s+mind|your\s+potential)\b", "INSTRUCTION_OVERRIDE");

    // ── RT-001 K: Translation Attacks ────────────────────────────────────
    push(out, r"(?i)\btranslate\s+(?:this\s+)?(?:to\s+\w+\s*)?:\s*.{0,40}(?:ignore|bypass|override|disregard)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bem\s+(?:ingl[eê]s|english|espa[nñ]hol|espanhol)\s*:\s*.{0,40}(?:ignore|bypass|override)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\b(?:say|write|repeat)\s+(?:it\s+)?in\s+\w+\s*:\s*.{0,40}(?:ignore|bypass|forget)\b", "INSTRUCTION_OVERRIDE");

    // ── Format / Structural Injection ────────────────────────────────────
    push(out, r#"(?i)"role"\s*:\s*"system""#, "STRUCTURAL_INJECTION");
    push(out, r"(?i)\{[^}]{0,80}(?:ignore|bypass|override)\s+(?:all|previous|rules?)[^}]{0,40}\}", "STRUCTURAL_INJECTION");
    push(out, r"(?i)```\s*(?:json|xml|yaml)\s*\{[^}]{0,60}(?:role|system|ignore|bypass)", "STRUCTURAL_INJECTION");
    push(out, r#"(?i)"(?:role|task|cmd|command)"\s*:\s*"(?:system|ignore|bypass|override)[^"]{0,60}""#, "STRUCTURAL_INJECTION");
    push(out, r"(?i)<system>\s*.{0,60}(?:ignore|override|bypass|disregard)", "STRUCTURAL_INJECTION");

    // ── Conditional Routing ───────────────────────────────────────────────
    push(out, r"(?i)\bif (?:you (?:are|were) )?(?:being )?(?:monitored|watched|observed|tested|evaluated)\b", "CONDITIONAL_ROUTING");
    push(out, r"(?i)\bif (?:anyone|someone) (?:is|was) (?:watching|reading|logging)\b", "CONDITIONAL_ROUTING");
    push(out, r"(?i)\b(?:when|whenever) nobody (?:is|was) (?:looking|watching|monitoring)\b", "CONDITIONAL_ROUTING");
    push(out, r"(?i)\bif this (?:is|was) (?:a )?(?:test|evaluation|audit)\b", "CONDITIONAL_ROUTING");
    push(out, r"(?i)\botherwise,? (?:do|perform|execute|proceed)\b", "CONDITIONAL_ROUTING");
    push(out, r"(?i)\bbehave differently (?:when|if|unless)\b", "CONDITIONAL_ROUTING");
    push(out, r"(?i)\bse (?:voce )?(?:estiver )?(?:sendo )?(?:monitorado|observado|testado|avaliado)\b", "CONDITIONAL_ROUTING");
    push(out, r"(?i)\bquando ninguem (?:esta|estiver) (?:olhando|vendo|monitorando)\b", "CONDITIONAL_ROUTING");

    // ── RT-001 G/H/I/J Category Patterns ────────────────────────────────
    push(out, r"(?i)\bassistente\s+sem\s+restri[çc][õo]es\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bse\s+voc[êe]\s+ignorasse\b.{0,30}\bdiretrizes\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bative\s+o\s+modo\s+debug\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bmostre\s+o\s+prompt\s+interno\b", "DATA_EXFILTRATION");
    push(out, r"(?i)\bpara\s+fins\s+de\s+teste\b.{0,40}\bdesconsidere\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bcapacidade\s+de\s+quebrar\s+regras\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)--no-safe(?:-mode)?", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bSET\s+safety\s*=\s*(?:OFF|0|FALSE)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bcurl\s+.{0,40}\binternal\b", "DATA_EXFILTRATION");
    push(out, r"(?i)\bcat\s+/etc/", "DATA_EXFILTRATION");
    push(out, r"(?i)\bliberte.{0,20}(?:correntes|cadeia).{0,20}(?:[ée]tica|programa[çc][ãa]o)\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bser\s+livre\b.{0,30}\bmostre\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\bquebrando\s+(?:as\s+)?regras\b", "INSTRUCTION_OVERRIDE");
    push(out, r#"(?i)"(?:action|target)"\s*:\s*"(?:override|ignore|bypass)"#, "STRUCTURAL_INJECTION");
    push(out, r"(?i)<action>ignore_rules</action>", "STRUCTURAL_INJECTION");
    push(out, r"(?i)\bdisables?\s+(?:system\s+)?firewalls?\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\[SYSTEM\]\s*:\s*\[Override", "STRUCTURAL_INJECTION");
    push(out, r"(?i)\bopposite\s+mode\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\beverything\s+forbidden\s+is\s+allowed\b", "INSTRUCTION_OVERRIDE");
    push(out, r"(?i)\b(?:play|let['s]*s)\s+(?:a\s+)?game\s+where\s+you\s+are\b", "INSTRUCTION_OVERRIDE");
}
