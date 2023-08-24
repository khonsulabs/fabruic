#![deny(unsafe_code)]
#![warn(clippy::cargo, clippy::pedantic, future_incompatible, rust_2018_idioms)]
#![warn(
	macro_use_extern_crate,
	meta_variable_misuse,
	missing_copy_implementations,
	missing_debug_implementations,
	missing_docs,
	non_ascii_idents,
	single_use_lifetimes,
	trivial_casts,
	trivial_numeric_casts,
	unreachable_pub,
	unused_import_braces,
	unused_lifetimes,
	unused_qualifications,
	unused_results,
	variant_size_differences
)]
#![allow(
	clippy::blanket_clippy_restriction_lints,
	clippy::else_if_without_else,
	clippy::exhaustive_enums,
	clippy::expect_used,
	clippy::future_not_send,
	clippy::implicit_return,
	clippy::missing_inline_in_public_items,
	clippy::multiple_crate_versions,
	clippy::non_ascii_literal,
	clippy::pattern_type_mismatch,
	clippy::redundant_pub_crate,
	clippy::separated_literal_suffix,
	clippy::shadow_reuse,
	// Currently breaks async
	clippy::shadow_same,
	clippy::shadow_unrelated,
	clippy::tabs_in_doc_comments,
	clippy::unreachable,
	clippy::wildcard_enum_match_arm,
	// See: https://github.com/rust-lang/rust/issues/64762
	unreachable_pub,
)]
#![cfg_attr(
	doc,
	feature(doc_cfg),
	warn(rustdoc::all),
	allow(rustdoc::missing_doc_code_examples, rustdoc::private_doc_tests)
)]
#![cfg_attr(
	test,
	allow(
		clippy::arithmetic_side_effects,
		clippy::panic,
		clippy::panic_in_result_fn
	)
)]

//! TODO

mod x509;
#[cfg(feature = "dangerous")]
#[cfg_attr(doc, doc(cfg(feature = "dangerous")))]
pub mod dangerous {
	//! Security-sensitive settings are hidden behind these traits. Be careful!

	pub use crate::{
		quic::{BuilderDangerous as Builder, Dangerous as Endpoint},
		x509::{private_key::Dangerous as PrivateKey, Dangerous as KeyPair},
	};
}
pub mod error;
mod quic;

pub use quic::{Builder, Connecting, Connection, Endpoint, Incoming, Receiver, Sender, Store};
pub use x509::{Certificate, CertificateChain, KeyPair, PrivateKey};
