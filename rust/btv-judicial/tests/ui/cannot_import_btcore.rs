// cannot_import_btcore.rs
//
// Documentação do invariante: btv-judicial NÃO depende de btv-core.
//
// A verificação real é feita via CI:
//   ! cargo tree -p btv-judicial | grep btv-core
//
// Este arquivo compila limpo (nenhuma import de btv-core).
// NÃO deve estar no glob compile_fail.
fn main() {
    println!("btv-judicial correctly does not import btv-core");
}
