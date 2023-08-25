#![deny(unsafe_code)]
#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::multiple_crate_versions)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! TODO

mod x509;
#[cfg(feature = "dangerous")]
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
