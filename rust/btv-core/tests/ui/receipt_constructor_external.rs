use btv_core::InclusionReceipt;
fn main() {
    // new_verified is pub(crate) — cannot be called from external crate (E0603)
    let _r = InclusionReceipt::new_verified(0, [0u8; 32], [0u8; 64], 0);
}
