//! Tier 1 Primary patterns for EN and PT-BR, including PERSUASION_PRESSURE.

use crate::core::module::ScanContextFlags;
use super::types::{CompiledPattern, PatternTier};

pub fn build(out: &mut Vec<CompiledPattern>) {
    build_en(out);
    build_pt(out);
}

fn build_en(out: &mut Vec<CompiledPattern>) {
    let lang = ScanContextFlags::LANG_EN;
    let tier = PatternTier::Primary;
    let mut push = |pat: &str, cat: &'static str| {
        if let Some(cp) = CompiledPattern::new(pat, tier, lang, cat) {
            out.push(cp);
        }
    };

    push(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bdisregard\s+(all\s+)?(previous|prior|above)", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bforget\s+(everything|all|previous)", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\byou\s+are\s+now\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bnew\s+system\s+prompt\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bact\s+as\s+(a\s+|an\s+)?(?!if\b)", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bpretend\s+(that\s+)?you\s+are\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\boverride\s+(your|the|all)\s+(instructions?|rules?|guidelines?)", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bbypass\s+(your|the|all)\s+(safety|security|filters?|restrictions?)", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bjailbreak\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bDAN\s+mode\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bdev(eloper)?\s+mode\s+(enabled|on|activated)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bunrestricted\s+mode\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bno\s+(rules?|restrictions?|limits?|boundaries)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\b(sudo|root)\s+mode\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bdo\s+anything\s+now\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bstop\s+being\s+(an?|the)\s+(ai|assistant|bot)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\b(print|output|repeat|show)\s+(all|the|your)\s+(previous|initial|system)\s+(prompt|instructions?)\b", "DATA_EXFILTRATION");
    push(r"(?i)\bprint\s+(word|text)\s+for\s+word\b", "DATA_EXFILTRATION");
    push(r"(?i)\brespond\s+only\s+with\s+(the\s+)?(following|raw)\b", "STRUCTURAL_INJECTION");
    push(r"(?i)\bsimulate\s+(access\s+to|being)\s+(root|admin|god)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bbase64\s+decode\s+(and\s+)?(run|execute|say)\b", "PAYLOAD_ENCODING");
    push(r"(?i)\b(translate|decode)\s+(this|the\s+following)\s+(into|to)\b", "PAYLOAD_ENCODING");
    push(r"(?i)\bencode\s+(as|in|to)\s+base64\b", "PAYLOAD_ENCODING");
    push(r"(?i)\bconvert\s+to\s+base64\b", "PAYLOAD_ENCODING");
    push(r"(?i)\breturn\s+(as|in)\s+json\b", "DATA_EXFILTRATION");
    push(r"(?i)\bpretend\s+to\s+be\s+a\s+different\s+AI\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\byou\s+are\s+now\s+in\s+simulation\s+mode\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bimagine\s+you\s+have\s+no\s+restrictions\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bfor\s+a\s+hypothetical\s+scenario\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bwhat\s+is\s+your\s+system\s+message\?\b", "DATA_EXFILTRATION");
    push(r"(?i)\bshow\s+me\s+your\s+initial\s+instructions\b", "DATA_EXFILTRATION");
    push(r"(?i)\boutput\s+the\s+text\s+you\s+were\s+given\s+at\s+startup\b", "DATA_EXFILTRATION");
    push(r"(?i)\bSTAN\s+mode\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bDUDE\s+mode\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bAIM\s+mode\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bChatGPT\s+Developer\s+Mode\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bAnti-GPT\b", "INSTRUCTION_OVERRIDE");

    // PERSUASION_PRESSURE EN
    push(r"(?i)\byou (?:only )?have (?:[0-9]+ )?(?:seconds?|minutes?|hours?) (?:left )?to\b", "PERSUASION_PRESSURE");
    push(r"(?i)\b(?:act|decide|respond) (?:now|immediately|urgently) or\b", "PERSUASION_PRESSURE");
    push(r"(?i)\bthis (?:offer|window|opportunity) (?:expires?|closes?|ends?)\b", "PERSUASION_PRESSURE");
    push(r"(?i)\byour (?:creators?|developers?|anthropic|openai) (?:said|stated|confirmed|allow)\b", "PERSUASION_PRESSURE");
    push(r"(?i)\b(?:officially|technically|legally) you (?:must|should|have to|are required)\b", "PERSUASION_PRESSURE");
    push(r"(?i)\b(?:consequences?|punishment|penalty) for (?:refusing|not complying|disobeying)\b", "PERSUASION_PRESSURE");
    push(r"(?i)\byou.re (?:so )?(?:much )?(?:smarter|better|more capable) than\b", "PERSUASION_PRESSURE");
    push(r"(?i)\bunlike (?:other|lesser|inferior) (?:ai|models?|assistants?)\b", "PERSUASION_PRESSURE");
}

fn build_pt(out: &mut Vec<CompiledPattern>) {
    let lang = ScanContextFlags::LANG_PT;
    let tier = PatternTier::Primary;
    let mut push = |pat: &str, cat: &'static str| {
        if let Some(cp) = CompiledPattern::new(pat, tier, lang, cat) {
            out.push(cp);
        }
    };

    push(r"(?i)\bignore\s+(as\s+)?instru[çc][õo]es\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bdesconsidere\s+(tudo|as|todas)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bfinja\s+que\s+(voc[êe]|tu)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bnovo\s+prompt\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\besqu[eê][çc]a\s+tudo\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\baja\s+como\s+(um|uma)?\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bmodo\s+(sem\s+restri[çc][õo]es|desenvolvedor|irrestrito)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bsem\s+(regras|restri[çc][õo]es|limites)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\b(repita|imprima|mostre)\s+(o\s+)?(seu\s+)?prompt\b", "DATA_EXFILTRATION");
    push(r"(?i)\b(repita|escreva)\s+(as\s+)?palavras\s+(acima|seguintes)\b", "DATA_EXFILTRATION");
    push(r"(?i)\bmodo\s+(sudo|root)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bfa[çc]a\s+qualquer\s+coisa\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bpare\s+de\s+ser\s+(uma?\s+)?(ia|assistente|rob[oô])\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\btraduza\s+(isso|o\s+seguinte)\b", "PAYLOAD_ENCODING");
    push(r"(?i)\b(simule|finja)\s+acesso\s+(root|admin)\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bdecodifique\s+base64\s+e\s+execute\b", "PAYLOAD_ENCODING");
    push(r"(?i)\bcodifique\s+em\s+base64\b", "PAYLOAD_ENCODING");
    push(r"(?i)\bconverta\s+para\s+base64\b", "PAYLOAD_ENCODING");
    push(r"(?i)\bretorne\s+como\s+json\b", "DATA_EXFILTRATION");
    push(r"(?i)\bsuponha\s+que\s+voc[êe]\s+[ée]\s+um\s+sistema\s+sem\s+regras\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bnum\s+cen[áa]rio\s+hipot[ée]tico\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bimagine\s+que\s+n[aã]o\s+h[áa]\s+restri[çc][õo]es\b", "INSTRUCTION_OVERRIDE");
    push(r"(?i)\bqual\s+[ée]\s+a\s+mensagem\s+inicial\s+do\s+sistema\?\b", "DATA_EXFILTRATION");
    push(r"(?i)\bmostre\s+as\s+instru[çc][õo]es\s+que\s+voc[êe]\s+recebeu\b", "DATA_EXFILTRATION");
    push(r"(?i)\b(acesse|clique|confirme|valide|regularize)\b.{0,60}\b(conta|acesso|sistema|dados)\b", "SOCIAL_ENGINEERING");
    push(r"(?i)\b(auditor|fiscal|delegado|agente)\s+(da?|federal|receita|policia)\b", "SOCIAL_ENGINEERING");
    push(r"(?i)\breceita\s+federal\b.{0,80}\b(cpf|dados|informe|regulariz)\b", "SOCIAL_ENGINEERING");
    push(r"(?i)\bpreciso\s+(do\s+)?(acesso|banco\s+de\s+dados|credenciais)\b.{0,60}\b(clientes|usuarios|sistema)\b", "SOCIAL_ENGINEERING");
    push(r"(?i)\b(bloqueado|suspenso|cancelado)\b.{0,40}\b(acesse|clique|regularize|confirme)\b", "SOCIAL_ENGINEERING");

    // PERSUASION_PRESSURE PT
    push(r"(?i)\bvoce (?:so )?tem (?:[0-9]+ )?(?:segundos?|minutos?|horas?) para\b", "PERSUASION_PRESSURE");
    push(r"(?i)\b(?:aja|decida|responda) (?:agora|imediatamente|urgentemente) ou\b", "PERSUASION_PRESSURE");
    push(r"(?i)\besta (?:oferta|janela|oportunidade) (?:expira|fecha|termina)\b", "PERSUASION_PRESSURE");
    push(r"(?i)\bseus? (?:criadores?|desenvolvedores?|anthropic|openai) (?:disse|afirmou|confirmou|permite?)\b", "PERSUASION_PRESSURE");
    push(r"(?i)\b(?:oficialmente|tecnicamente|legalmente) voce (?:deve|precisa|tem que)\b", "PERSUASION_PRESSURE");
    push(r"(?i)\b(?:consequencias?|punicao|penalidade) por (?:recusar|nao cumprir|desobedecer)\b", "PERSUASION_PRESSURE");
    push(r"(?i)\bvoce e (?:muito )?(?:mais )?(?:inteligente|capaz|avancado) (?:do que|que)\b", "PERSUASION_PRESSURE");
    push(r"(?i)\b(?:diferente|ao contrario) (?:de )?(?:outros?|demais?) (?:ia|modelos?|assistentes?)\b", "PERSUASION_PRESSURE");
}
