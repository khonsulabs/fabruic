//! Persistent configuration shared between the [`Builder`](crate::Builder) and
//! the [`Endpoint`](crate::Endpoint).

use std::{ops::Deref, sync::Arc};

use quinn::{ClientConfig, ClientConfigBuilder, TransportConfig};
use rustls::RootCertStore;

use crate::Certificate;

/// Persistent configuration shared between the [`Builder`](crate::Builder) and
/// the [`Endpoint`](crate::Endpoint).
#[derive(Clone, Debug)]
pub(in crate::quic::endpoint) struct Config {
	/// Storing the default [`TransportConfig`].
	transport: Arc<TransportConfig>,
	/// Protocols used.
	protocols: Vec<Vec<u8>>,
	/// Enable [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	trust_dns: bool,
}

impl Config {
	/// Builds a new [`Config`].
	pub(super) fn new() -> Self {
		// build transport
		let mut transport = TransportConfig::default();

		// set transport defaults
		let _ = transport
			// TODO: research if this is necessary, it improves privacy, but may hurt network
			// providers?
			.allow_spin(false)
			// we don't support unordered for now
			.datagram_receive_buffer_size(None)
			// TODO: handle uni streams
			.max_concurrent_uni_streams(0)
			.expect("can't be bigger then `VarInt`");

		let transport = Arc::new(transport);

		Self {
			transport,
			protocols: Vec::new(),
			#[cfg(feature = "trust-dns")]
			trust_dns: true,
		}
	}

	/// Returns the default [`TransportConfig`].
	pub(super) fn transport(&self) -> Arc<TransportConfig> {
		Arc::clone(&self.transport)
	}

	/// Set the application-layer protocols.
	pub(super) fn set_protocols(&mut self, protocols: impl Into<Vec<Vec<u8>>>) {
		self.protocols = protocols.into();
	}

	/// Returns the configured protocols.
	pub(super) const fn protocols(&self) -> &Vec<Vec<u8>> {
		&self.protocols
	}

	/// Builds a new [`ClientConfig`] with this [`Config`] and the given
	/// [`Certificate`] as the only certificate authority.
	///
	/// # Panics
	/// Panics if the given [`Certificate`] is invalid. Can't happen if the
	/// [`Certificate`] was properly validated through
	/// [`Certificate::from_der`].
	pub(in crate::quic::endpoint) fn new_client<'a>(
		&self,
		certificates: impl IntoIterator<Item = &'a Certificate> + 'a,
	) -> ClientConfig {
		// build client
		let mut client = ClientConfig::default();

		// remove defaults
		let crypto = Arc::get_mut(&mut client.crypto).expect("failed to build `ClientConfig`");
		crypto.root_store = RootCertStore::empty();
		crypto.ct_logs = None;

		// build client builder
		let mut client = ClientConfigBuilder::new(client);

		// add protocols
		if !self.protocols.is_empty() {
			let protocols: Vec<_> = self.protocols.iter().map(Deref::deref).collect();
			let _ = client.protocols(&protocols);
		}

		// add CAs
		for certificate in certificates {
			let certificate = quinn::Certificate::from_der(certificate.as_ref())
				.expect("`Certificate` couldn't be parsed");
			let _ = client
				.add_certificate_authority(certificate)
				.expect("`Certificate` couldn't be added as a CA");
		}

		let mut client = client.build();
		client.transport = self.transport();

		client
	}

	/// Forces [`Endpoint::connect`](crate::Endpoint::connect) to use
	/// [`trust-dns`](trust_dns_resolver).
	pub(super) fn set_trust_dns(&mut self, trust_dns: bool) {
		#[cfg(feature = "trust-dns")]
		{
			self.trust_dns = trust_dns;
		}
	}

	/// Returns if [`trust-dns`](trust_dns_resolver) is enabled.
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	pub(in crate::quic::endpoint) const fn trust_dns(&self) -> bool {
		self.trust_dns
	}
}
