#![allow(box_pointers)]

//! [`Error`](std::error::Error) for this [`crate`].
// TODO: error type is becoming too big, split it up

pub use std::{io::Error as IoError, net::AddrParseError};

pub use bincode::ErrorKind;
pub use quinn::{ConnectError, ConnectionError, EndpointError, ReadError, WriteError};
use thiserror::Error;
#[cfg(feature = "trust-dns")]
#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
pub use trust_dns_resolver::error::ResolveError;
#[cfg(feature = "trust-dns")]
#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
pub use url::ParseError as UrlParseError;
pub use webpki::Error as WebPkiError;
pub use x509_parser::{error::X509Error, nom::Err};

/// [`Result`](std::result::Result) type for this [`crate`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// [`Error`](std::error::Error) for this [`crate`].
#[derive(Debug, Error)]
pub enum Error {
	/// Failed to parse the given certificate.
	#[error("Failed parsing certificate: {error}")]
	ParseCertificate {
		/// The certificate passed to
		/// [`from_der`](crate::Certificate::from_der).
		certificate: Vec<u8>,
		/// The parsing error.
		error: ParseCertificate,
	},
	/// Data passed to generate [`Certificate`](crate::Certificate) with
	/// [`from_der`](crate::Certificate::from_der) found to contain
	/// uncorrelated bytes.
	#[error("Found dangling bytes in `Certificate`")]
	DanglingCertificate {
		/// The certificate passed to
		/// [`from_der`](crate::Certificate::from_der).
		certificate: Vec<u8>,
		/// The dangling bytes.
		dangling: Vec<u8>,
	},
	/// [`Certificate`](crate::Certificate) has expired.
	#[error("`Certificate` has expired")]
	ExpiredCertificate(Vec<u8>),
	/// [`Certificate`](crate::Certificate) is missing a domain name.
	#[error("`Certificate` is missing a domain name")]
	DomainCertificate(Vec<u8>),
	/// Failed to parse the given private key.
	#[error("Failed parsing private key")]
	ParsePrivateKey,
	/// Parsing a [`SocketAddr`](std::net::SocketAddr) from a [`str`] failed.
	#[error("Failed parsing socket: {0}")]
	ParseAddress(AddrParseError),
	/// Returned by [`Endpoint`](crate::Endpoint) when failing to bind the
	/// socket on the given `address`.
	#[error("Failed to bind socket: {0}")]
	BindSocket(EndpointError),
	/// Failed to parse URL.
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	#[error("Error parsing URL: {0}")]
	ParseUrl(UrlParseError),
	/// URL didn't contain a domain.
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	#[error("URL without a domain is invalid")]
	Domain,
	/// URL didn't contain a port.
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	#[error("URL without a port is invalid")]
	Port,
	/// Failed to resolve domain to IP address with
	/// [`trust-dns`](trust_dns_resolver).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	#[error("Error resolving domain with trust-dns: {0}")]
	ResolveTrustDns(Box<ResolveError>),
	/// Failed to resolve domain to IP address with
	/// [`ToSocketAddrs`](std::net::ToSocketAddrs).
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	#[error("Error resolving domain with `ToSocketAddrs`: {0}")]
	ResolveStdDns(IoError),
	/// Found no IP address for that domain.
	#[cfg(feature = "trust-dns")]
	#[cfg_attr(doc, doc(cfg(feature = "trust-dns")))]
	#[error("Found no IP address for that domain")]
	NoIp,
	/// Returned by [`Endpoint::local_address`](crate::Endpoint::local_address)
	/// when failing to aquire the local address.
	#[error("Failed to aquire local address: {0}")]
	LocalAddress(IoError),
	/// Attempting to close something that is already closed.
	#[error("This is already closed")]
	AlreadyClosed,
	/// Returned by
	/// [`Endpoint::connect_pinned`](crate::Endpoint::connect_pinned) if
	/// the passed [`Certificate`](crate::Certificate) has multiple domains.
	#[error("Using a `Certificate` with multiple domains for direction connection is invalid")]
	MultipleDomains,
	/// Returned by [`Endpoint::connect`](crate::Endpoint::connect) if
	/// configuration needed to connect to a peer is faulty.
	#[error("Error in configuration to connect to a peer: {0}")]
	ConnectConfig(ConnectError),
	/// Returned by [`Connecting::accept`](crate::Connecting::accept) if
	/// connecting to the peer failed.
	#[error("Error on connecting to a remote address: {0}")]
	Connecting(ConnectionError),
	/// Returned by [`Connection`](crate::Connection)
	/// [`Stream`](futures_util::stream::Stream) when receiving a new stream
	/// failed.
	#[error("Error on receiving a new stream: {0}")]
	ReceiveStream(ConnectionError),
	/// Returned by [`Connection::open_stream`](crate::Connection::open_stream)
	/// if opening a stream failed.
	#[error("Error on opening a stream: {0}")]
	OpenStream(ConnectionError),
	/// Returned by [`Sender::finish`](crate::Sender::finish) if
	/// [`Sender`](crate::Sender) failed to write into the stream.
	#[error("Error writing to a stream: {0}")]
	Write(WriteError),
	/// Returned by [`Sender::finish`](crate::Sender::finish) if
	/// [`Sender`](crate::Sender) failed to finish a stream.
	#[error("Error finishing a stream: {0}")]
	Finish(WriteError),
	/// Returned by [`Sender::send`](crate::Sender::send) if the stream was
	/// closed by [`Sender::finish`](crate::Sender::finish) or the
	/// [`Connection`](crate::Connection) or [`Endpoint`](crate::Endpoint) was
	/// closed or dropped.
	#[error("Stream was closed")]
	Send,
	/// Returned by [`Sender::send`](crate::Sender::send) if
	/// [`serialization`](serde::Serialize) failed.
	#[error("Error serializing to a stream: {0}")]
	Serialize(ErrorKind),
	/// Returned by [`Receiver::close`](crate::Receiver::close) if
	/// [`Receiver`](crate::Receiver) failed to read from a stream.
	#[error("Error reading from a stream: {0}")]
	Read(ReadError),
	/// Returned by [`Receiver::finish`](crate::Receiver::finish) if
	/// [`Receiver`](crate::Receiver) failed to
	/// [`deserialize`](serde::Deserialize) from a stream.
	#[error("Error deserializing from a stream: {0}")]
	Deserialize(ErrorKind),
	/// Returned by [`Incoming::type`](crate::Incoming::type) if the peer
	/// closed the stream before sending the type.
	#[error("Stream was closed before sending a type")]
	NoType,
}

/// Possible certificate parsing errors.
#[derive(Debug, Error)]
pub enum ParseCertificate {
	/// [`Error`](std::error::Error) returned by [`webpki`].
	#[error(transparent)]
	WebPki(WebPkiError),
	/// [`Error`](std::error::Error) returned by [`x509_parser`].
	#[error(transparent)]
	X509(Err<X509Error>),
}
