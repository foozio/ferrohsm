//! PKCS#11 interface implementation for FerroHSM
//!
//! This crate provides a PKCS#11 compatible interface that maps cryptographic
//! operations onto FerroHSM's core capabilities.

#[macro_use]
extern crate lazy_static;

pub mod functions;
pub mod hardware;
pub mod object;
pub mod session;
pub mod slot;
pub mod types;

// Re-export cryptoki types for convenience
pub use cryptoki::types::*;

// PKCS#11 function exports
pub use functions::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}