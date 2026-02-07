//! Atlas Policy — policy engine and quality gating logic.

pub mod baseline;
pub mod gate;
pub mod policy;

pub use policy::{
    default_policy, load_policy, load_policy_from_str, merge_policies, CategoryOverrides, Policy,
    PolicyError, Thresholds,
};
