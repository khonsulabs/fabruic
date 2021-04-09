#![allow(box_pointers)]

//! [`Error`](std::error::Error) for this [`crate`].
// TODO: error type is becoming too big, split it up

pub use std::{io::Error as IoError, net::AddrParseError};

pub use bincode::ErrorKind;
pub use quinn::{ConnectError, ConnectionError, EndpointError, ParseError, ReadError, WriteError};
pub use ring::error::KeyRejected;
pub use rustls::TLSError;
use thiserror::Error;
#[cfg(feature = "dns")]
#[cfg_attr(doc, doc(cfg(feature = "dns")))]
pub use trust_dns_resolver::error::ResolveError;
pub use webpki::Error as WebPkiError;
#[cfg(feature = "certificate")]
#[cfg_attr(doc, doc(cfg(feature = "certificate")))]
pub use x509_parser::{error::X509Error, nom::Err};

/// [`Result`](std::result::Result) type for this [`crate`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// [`Error`](std::error::Error) for this [`crate`].
#[derive(Debug, Error)]
pub enum Error {
	/// Failed to parse the given certificate.
	#[cfg(feature = "certificate")]
	#[cfg_attr(doc, doc(cfg(feature = "certificate")))]
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
	#[cfg(feature = "certificate")]
	#[cfg_attr(doc, doc(cfg(feature = "certificate")))]
	#[error("Found dangling bytes in `Certificate`")]
	DanglingCertificate {
		/// The certificate passed to
		/// [`from_der`](crate::Certificate::from_der).
		certificate: Vec<u8>,
		/// The dangling bytes.
		dangling: Vec<u8>,
	},
	/// [`Certificate`](crate::Certificate) has expired.
	#[cfg(feature = "certificate")]
	#[cfg_attr(doc, doc(cfg(feature = "certificate")))]
	#[error("`Certificate` has expired")]
	ExpiredCertificate(Vec<u8>),
	/// [`Certificate`](crate::Certificate) is missing a domain name.
	#[cfg(feature = "certificate")]
	#[cfg_attr(doc, doc(cfg(feature = "certificate")))]
	#[error("`Certificate` is missing a domain name")]
	DomainCertificate(Vec<u8>),
	/// Failed to parse the given private key.
	#[error("Failed parsing private key")]
	ParsePrivateKey,
	/// Parsing a [`SocketAddr`](std::net::SocketAddr) from a [`str`] failed.
	#[error("Failed parsing socket: {0}")]
	ParseAddress(AddrParseError),
	/// Returned by [`Endpoint`](crate::Endpoint) when failing to parse the
	/// given [`Certificate`](crate::Certificate).
	#[error("Failed parsing certificate: {0}")]
	Certificate(ParseError),
	/// Returned by [`Endpoint`](crate::Endpoint) when failing to parse the
	/// given [`PrivateKey`](crate::PrivateKey).
	#[error("Failed parsing private key: {0}")]
	PrivateKey(ParseError),
	/// Returned by [`Endpoint`](crate::Endpoint) when failing to pair the given
	/// [`Certificate`](crate::Certificate) and
	/// [`PrivateKey`](crate::PrivateKey).
	#[error("Invalid certificate key pair: {0}")]
	InvalidKeyPair(TLSError),
	/// Returned by [`Endpoint`](crate::Endpoint) when failing to add the given
	/// [`Certificate`](crate::Certificate) as a certificate authority.
	#[error("Invalid certificate: {0}")]
	InvalidCertificate(WebPkiError),
	/// Returned by [`Endpoint`](crate::Endpoint) when failing to bind the
	/// socket on the given `address`.
	#[error("Failed to bind socket: {0}")]
	BindSocket(EndpointError),
	/// Failed to resolve domain to IP address.
	#[cfg(feature = "dns")]
	#[cfg_attr(doc, doc(cfg(feature = "dns")))]
	#[error("Error resolving domain: {0}")]
	Resolve(Box<ResolveError>),
	/// Found no IP address for that domain.
	#[cfg(feature = "dns")]
	#[cfg_attr(doc, doc(cfg(feature = "dns")))]
	#[error("Found no IP address for that domain")]
	NoIp,
	/// Returned by [`Endpoint`](crate::Endpoint)
	/// [`Stream`](futures_util::stream::Stream) when receiving a new stream
	/// failed.
	#[error("Error on receiving a new connection: {0}")]
	IncomingConnection(ConnectionError),
	/// Returned by [`Endpoint::local_address`](crate::Endpoint::local_address)
	/// when failing to aquire the local address.
	#[error("Failed to aquire local address: {0}")]
	LocalAddress(IoError),
	/// Attempting to close something that is already closed.
	#[error("This is already closed")]
	AlreadyClosed,
	/// Returned by [`Endpoint::connect`](crate::Endpoint::connect) if
	/// establishing a connection to the given `address` failed.
	#[error("Error on establishing a connection to a remote address: {0}")]
	Connect(ConnectError),
	/// Returned by [`Endpoint::connect`](crate::Endpoint::connect) if
	/// connecting to the remote `address` failed.
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
}

/// Possible certificate parsing errors.
#[cfg(feature = "certificate")]
#[derive(Debug, Error)]
pub enum ParseCertificate {
	/// [`Error`](std::error::Error) returned by [`webpki`].
	#[error(transparent)]
	WebPki(WebPkiError),
	/// [`Error`](std::error::Error) returned by [`x509_parser`].
	#[error(transparent)]
	X509(Err<X509Error>),
}
