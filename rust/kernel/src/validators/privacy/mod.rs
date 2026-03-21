//! Privacy Validators (LGPD Rights & Consent)
pub mod consent;
pub mod revocation;
pub mod geo_location; // Cenário 26: Over-sharing GPS (PROP-039)

pub use consent::ConsentValidator;
pub use revocation::ConsentRevocationValidator;
pub use geo_location::{GeoLocationFinding, GeoMatchKind, scan as scan_geo_location};