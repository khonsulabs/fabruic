#![allow(clippy::module_name_repetitions)]

//! [`Error`](std::error::Error) for this [`crate`].
// TODO: error type is becoming too big, split it up

use std::{
	fmt::{self, Debug, Formatter},
	io,
};

pub use bincode::ErrorKind;
use quinn::ConnectionClose;
pub use quinn::{ConnectError, ConnectionError, ReadError, WriteError};
use thiserror::Error;
#[cfg(feature = "trust-dns")]
pub use trust_dns_resolver::error::ResolveError;
pub use url::ParseError;
pub use webpki::Error;
pub use x509_parser::{error::X509Error, nom::Err};
use zeroize::Zeroize;

/// Error constructing [`Certificate`](crate::Certificate) with
/// [`Certificate::from_der`](crate::Certificate::from_der).
#[derive(Clone, Debug, Error, PartialEq)]
#[error("Error constructing `Certificate` from bytes: {error}")]
pub struct Certificate {
	/// The error.
	#[source]
	pub error: CertificateError,
	/// The bytes used to build the [`Certificate`](crate::Certificate).
	pub certificate: Vec<u8>,
}

/// Error constructing [`Certificate`](crate::Certificate) with
/// [`Certificate::from_der`](crate::Certificate::from_der).
#[derive(Clone, Debug, Error, PartialEq)]
pub enum CertificateError {
	/// [`Error`](std::error::Error) returned by [`webpki`].
	#[error(transparent)]
	WebPki(Error),
	/// [`Error`](std::error::Error) returned by [`x509_parser`].
	#[error(transparent)]
	X509(Err<X509Error>),
	/// Bytes passed contain uncorrelated bytes.
	#[error("Found dangling bytes in `Certificate`")]
	Dangling(Vec<u8>),
	/// [`Certificate`](crate::Certificate) has expired.
	#[error("`Certificate` has expired")]
	Expired,
	/// [`Certificate`](crate::Certificate) is missing a domain name.
	#[error("`Certificate` is missing a domain name")]
	Domain,
}

/// Failed to parse the given private key with
/// [`PrivateKey::from_der`](crate::PrivateKey::from_der).
#[derive(Clone, Eq, Error, Hash, Ord, PartialEq, PartialOrd, Zeroize)]
#[error("Failed parsing private key")]
#[zeroize(drop)]
pub struct PrivateKey(pub Vec<u8>);

impl Debug for PrivateKey {
	fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
		formatter
			.debug_tuple("PrivateKey")
			.field(&"[[redacted]]")
			.finish()
	}
}

/// Failed to pair given [`CertificateChain`](crate::CertificateChain) and
/// [`PrivateKey`](crate::PrivateKey) with
/// [`KeyPair::from_parts`](crate::KeyPair::from_parts).
#[derive(Clone, Debug, Eq, Error, Hash, Ord, PartialEq, PartialOrd)]
#[error("Failed pairing `Certificate` and `PrivateKey`")]
pub struct KeyPair {
	/// [`CertificateChain`](crate::CertificateChain).
	certificate: crate::CertificateChain,
	/// [`PrivateKey`](crate::PrivateKey).
	private_key: crate::PrivateKey,
}

/// Failed to verify the certificate chain with
/// [`CertificateChain::from_certificates`].
///
/// [`CertificateChain::from_certificates`]:
/// crate::CertificateChain::from_certificates
#[derive(Clone, Debug, Eq, Error, Hash, Ord, PartialEq, PartialOrd)]
#[error("Failed verifiying certificate chhain")]
pub struct CertificateChain(Vec<crate::Certificate>);

/// Attempting to close something that is already closed.
#[derive(Clone, Copy, Debug, Eq, Error, Hash, Ord, PartialEq, PartialOrd)]
#[error("This is already closed")]
pub struct AlreadyClosed;

/// Error during construction of [`Endpoint`](crate::Endpoint)
/// with [`Builder::build`](crate::Builder::build).
#[derive(Debug, Error)]
#[error("Error constructing `Endpoint` with `Builder`: {error}")]
pub struct Builder {
	/// Configuration error.
	#[source]
	pub error: Config,
	/// Recovered [`Builder`](crate::Builder) for re-use.
	pub builder: crate::Builder,
}

/// Configuration error.
#[derive(Debug, Error)]
pub enum Config {
	/// The error binding [`Endpoint`](crate::Endpoint).
	#[error("Error binding socket during construction of `Endpoint`: {0}")]
	Bind(io::Error),
	/// Error aquiring or parsing root certificates from the OS.
	#[error(transparent)]
	NativeCert(#[from] OsStore),
	/// Returned when timeout chosen is equal or bigger than 2^62 ms.
	#[error("Invalid timeout, can't exceed 2^62 ms")]
	MaxIdleTimeout,
}

/// Error aquiring or parsing root certs from OS.
#[derive(Debug, Error)]
pub enum OsStore {
	/// Failed to aquire root certs from OS.
	#[error("Error aquiring root certificates from the OS: {0}")]
	Aquire(io::Error),
	/// Failed to parse root certs from OS.
	#[error("Error parsing root certificates from the OS: {0}")]
	Parse(Error),
}

/// Error connecting to a server with
/// [`Endpoint::connect`](crate::Endpoint::connect).
#[derive(Debug, Error)]
pub enum Connect {
	/// The passed [`Certificate`](crate::Certificate) has multiple domains,
	/// this is not supported with
	/// [`Endpoint::connect_pinned`](crate::Endpoint::connect_pinned).
	#[error(
		"Using a `Certificate` with multiple domains for connecting with a pinned server \
		 certificate is not supported"
	)]
	MultipleDomains,
	/// Failed to parse URL.
	#[error("Error parsing URL: {0}")]
	ParseUrl(ParseError),
	/// URL didn't contain a domain.
	#[error("URL without a domain is invalid")]
	Domain,
	/// URL didn't contain a port.
	#[error("URL without a port is invalid")]
	Port,
	/// Failed to parse domain.
	#[error("Error parsing domain: {0}")]
	ParseDomain(ParseError),
	/// Failed to resolve domain with [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[error("Error resolving domain with trust-dns: {0}")]
	TrustDns(#[from] Box<ResolveError>),
	/// Failed to resolve domain with
	/// [`ToSocketAddrs`](std::net::ToSocketAddrs).
	#[error("Error resolving domain with `ToSocketAddrs`: {0}")]
	StdDns(io::Error),
	/// Found no IP address for that domain.
	#[error("Found no IP address for that domain")]
	NoIp,
	/// Configuration needed to connect to a server is faulty.
	#[error("Error in configuration to connect to server: {0}")]
	ConnectConfig(#[from] ConnectError),
	/// Configuration faulty.
	#[error("Error in configuration: {0}")]
	Config(#[from] Config),
}

/// Error receiving stream from peer with [`Stream`](futures_util::Stream)
/// on from [`Connection`](crate::Connection).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("Error receiving connection from peer: {0}")]
pub struct Connection(pub ConnectionError);

/// Error completing connection with peer with
/// [`Incoming::type`](crate::Incoming::type) or
/// [`Incoming::accept`](crate::Incoming::accept).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum Connecting {
	/// The peer did not accept any of the protocols specified.
	#[error("Peer failed to negotiate a protocol")]
	ProtocolMismatch,
	/// An error completing the connection.
	#[error("Error completing connection with peer: {0}")]
	Connection(ConnectionError),
}

impl From<ConnectionError> for Connecting {
	fn from(err: ConnectionError) -> Self {
		match err {
			ConnectionError::ConnectionClosed(ConnectionClose {
				error_code,
				frame_type: None,
				reason,
			}) if reason.as_ref() == b"peer doesn't support any known protocol"
				&& error_code.to_string() == "the cryptographic handshake failed: error 120" =>
				Self::ProtocolMismatch,
			other => Self::Connection(other),
		}
	}
}

/// Error opening a new stream to peer with
/// [`Connection::open_stream`](crate::Connection::open_stream).
#[derive(Debug, Error)]
pub enum Stream {
	/// Opening a new stream with
	/// [`Connection::open_stream`](crate::Connection::open_stream) failed.
	#[error("Error opening a new stream to peer: {0}")]
	Open(#[from] ConnectionError),
	/// Sending the type information to peer failed.
	#[error("Error sending type information to peer: {0}")]
	Sender(#[from] Sender),
}

/// Error receiving type information from [`Incoming`](crate::Incoming) stream.
#[derive(Debug, Error)]
pub enum Incoming {
	/// Failed receiving type information from [`Incoming`](crate::Incoming)
	/// stream.
	#[error("Error receiving type information from `Incoming` stream: {0}")]
	Receiver(Receiver),
	/// [`Incoming`](crate::Incoming) was closed before type information could
	/// be received.
	#[error("Incoming stream was closed")]
	Closed,
}

/// Error receiving a message from a [`Receiver`](crate::Receiver).
#[derive(Debug, Error)]
pub enum Receiver {
	/// Failed to read from a [`Receiver`](crate::Receiver).
	#[error("Error reading from `Receiver`: {0}")]
	Read(#[from] ReadError),
	/// Failed to [`Deserialize`](serde::Deserialize) a message from a
	/// [`Receiver`](crate::Receiver).
	#[error("Error deserializing a message from `Receiver`: {0}")]
	Deserialize(#[from] ErrorKind),
}

/// Error sending a message to a [`Sender`](crate::Sender).
#[derive(Debug, Error)]
pub enum Sender {
	/// Failed to [`Serialize`](serde::Serialize) a message for a
	/// [`Sender`](crate::Sender).
	#[error("Error serializing a message to `Sender`: {0}")]
	Serialize(ErrorKind),
	/// Failed to write to a [`Sender`](crate::Sender).
	#[error("Error writing to `Sender`: {0}")]
	Write(#[from] WriteError),
	/// [`Sender`] is closed.
	#[error(transparent)]
	Closed(#[from] AlreadyClosed),
}

impl From<Box<ErrorKind>> for Sender {
	fn from(error: Box<ErrorKind>) -> Self {
		Self::Serialize(*error)
	}
}
