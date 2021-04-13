//! Persistent configuration shared between the [`Builder`](crate::Builder) and
//! the [`Endpoint`](crate::Endpoint).

/// Persistent configuration shared between the [`Builder`](crate::Builder) and
/// the [`Endpoint`](crate::Endpoint).
#[derive(Clone, Debug, Default)]
pub(in crate::quic::endpoint) struct Config {
	/// Protocols used.
	protocols: Option<Vec<Vec<u8>>>,
}

impl Config {
	/// Set the application-layer protocols.
	pub(super) fn set_protocols(&mut self, protocols: &[&[u8]]) {
		self.protocols = Some(
			protocols
				.iter()
				.map(|protocol| (*protocol).to_owned())
				.collect(),
		);
	}
}
