// circuits/statistical_consistency/src/main.nr
// Paper 3, §3.3 — Circuit C: epsilon-statistical consistency
//
// STATUS: Reference implementation. Compilavel quando Noir toolchain estiver
// instalada (Semanas 18-20 do roadmap).
// Gate count estimado: ~5.2M (BN254/Barretenberg)
//
// PUBLIC INPUTS:
//   com_before[2]  — Pedersen commitment antes da redacao
//   com_after[2]   — Pedersen commitment depois da redacao
//   epsilon        — tolerancia (fixed-point, multiplicado por 10^6)
//   num_groups     — numero de grupos protegidos
//
// PRIVATE INPUTS (WITNESS):
//   stats_before[] — (total, approved, denied) antes
//   stats_after[]  — (total, approved, denied) depois
//   blinding_b     — fator de blinding antes
//   blinding_a     — fator de blinding depois

global MAX_GROUPS: u32 = 16;
global EPSILON_SCALE: u64 = 1_000_000; // fixed-point scale

struct GroupStats {
    total:    u64,
    approved: u64,
    denied:   u64,
}

fn fixed_div(num: u64, den: u64) -> u64 {
    // Returns num/den * EPSILON_SCALE (integer division)
    // Returns 0 if den == 0 (edge case: empty group)
    if den == 0 { 0 } else { (num * EPSILON_SCALE) / den }
}

fn abs_diff(a: u64, b: u64) -> u64 {
    if a >= b { a - b } else { b - a }
}

fn main(
    // Public inputs
    com_before:  pub [Field; 2],
    com_after:   pub [Field; 2],
    epsilon:     pub u64,
    num_groups:  pub u32,

    // Private witness
    stats_before: [GroupStats; MAX_GROUPS],
    stats_after:  [GroupStats; MAX_GROUPS],
    blinding_b:   Field,
    blinding_a:   Field,
) {
    // Check 1: Pedersen commitment before
    // let com_b = pedersen_commitment([stats_before...], blinding_b);
    // assert(com_b == com_before);
    // TODO: habilitar quando pedersen.nr estiver implementado

    // Check 2: Pedersen commitment after
    // let com_a = pedersen_commitment([stats_after...], blinding_a);
    // assert(com_a == com_after);

    // Check 3 + 4 + 5: epsilon-consistency, direction, non-negativity
    for i in 0..MAX_GROUPS {
        if (i as u32) < num_groups {
            let sb = stats_before[i];
            let sa = stats_after[i];

            // Non-negativity
            assert(sa.approved <= sa.total);
            assert(sa.denied   <= sa.total);
            assert(sa.approved + sa.denied == sa.total);

            // Epsilon-consistency: |rate_before - rate_after| <= epsilon
            let rate_b = fixed_div(sb.approved, sb.total);
            let rate_a = fixed_div(sa.approved, sa.total);
            let delta  = abs_diff(rate_b, rate_a);
            assert(delta <= epsilon);

            // Direction: redacao nao pode PIORAR a taxa de aprovacao
            // rate_after >= rate_before - epsilon
            if rate_b > epsilon {
                assert(rate_a >= rate_b - epsilon);
            }
        }
    }
}
