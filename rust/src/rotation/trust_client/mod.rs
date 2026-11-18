//! Client-side rotation controller and its refresh state (Linux only).

use super::*;

pub(in crate::rotation) mod controller;
#[cfg(test)]
mod controller_tests;
pub(in crate::rotation) mod refresh_state;
#[cfg(test)]
pub(in crate::rotation) mod refresh_tests;
