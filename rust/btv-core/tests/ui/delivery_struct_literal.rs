#![allow(unreachable_code)]
use btv_core::DeliveryToken;
fn main() {
    // All fields are private — this must fail with E0451
    let _d = DeliveryToken {
        verdict_record: todo!(),
        receipt_wire: todo!(),
    };
}
