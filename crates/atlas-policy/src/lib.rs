//! Atlas Policy — policy engine and quality gating logic.

pub mod baseline;
pub mod gate;
pub mod policy;

pub use policy::{
    CategoryOverrides, Policy, PolicyError, Suppression, Thresholds, default_policy, load_policy,
    load_policy_from_str, merge_policies,
};
