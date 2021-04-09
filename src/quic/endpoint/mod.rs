//! Starting point to create a QUIC enabled network socket.

mod builder;

use std::{
	fmt::{self, Debug, Formatter},
	net::SocketAddr,
	pin::Pin,
	task::{Context, Poll},
};

pub use builder::Builder;
use flume::{r#async::RecvStream, Sender};
use futures_channel::oneshot::{self, Receiver};
use futures_util::{
	stream::{FusedStream, Stream},
	StreamExt,
};
use quinn::{ClientConfig, NewConnection, ServerConfig, VarInt};
#[cfg(feature = "dns")]
use trust_dns_resolver::{
	config::{ResolverConfig, ResolverOpts},
	TokioAsyncResolver,
};

use super::Task;
use crate::{
	certificate::{Certificate, PrivateKey},
	Connection, Error, Result,
};

/// Represents a socket using the QUIC protocol to communicate with peers.
/// Receives incoming [`Connection`]s through [`Stream`].
#[derive(Clone)]
pub struct Endpoint {
	/// Initiate new connections or close socket.
	endpoint: quinn::Endpoint,
	/// Receiving new incoming connections.
	receiver: RecvStream<'static, Result<Connection>>,
	/// Task handle handling new incoming connections.
	task: Task<()>,
}

impl Debug for Endpoint {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Server")
			.field("endpoint", &self.endpoint)
			.field("receiver", &"RecvStream<Connection>")
			.field("task", &self.task)
			.finish()
	}
}

impl Endpoint {
	/// Builds a new [`Builder`]. See [`Builder`] methods for defaults.
	#[must_use]
	pub fn builder() -> Builder {
		Builder::new()
	}

	/// Encapsulates common construction paths for
	/// [`new_server`](Endpoint::new_server) and
	/// [`new_client`](Endpoint::new_client). Must be called from inside the
	/// Tokio [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// [`Error::BindSocket`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// If not called from inside the Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	fn new(
		address: SocketAddr,
		client: ClientConfig,
		server: Option<ServerConfig>,
	) -> Result<Self> {
		// configure endpoint for server and client
		let mut endpoint_builder = quinn::Endpoint::builder();
		let _ = endpoint_builder.default_client_config(client);

		// client don't need a server configuration
		let server = server.map_or(false, |server| {
			let _ = endpoint_builder.listen(server);
			true
		});

		// build endpoint
		let (endpoint, incoming) = endpoint_builder.bind(&address).map_err(Error::BindSocket)?;

		// create channels that will receive incoming `Connection`s
		let (sender, receiver) = flume::unbounded();
		let receiver = receiver.into_stream();

		// only servers will have a running task
		let task = if server {
			// spawn task handling incoming `Connection`s
			let (shutdown_sender, shutdown_receiver) = oneshot::channel();
			Task::new(
				Self::incoming(incoming, sender, shutdown_receiver),
				shutdown_sender,
			)
		} else {
			Task::empty()
		};

		Ok(Self {
			endpoint,
			receiver,
			task,
		})
	}

	/// Simplified version of creating a client. See [`Builder`] for more
	/// sophisticated configuration. Must be called from inside the Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// - [`Error::Certificate`] if the [`Certificate`] couldn't be parsed
	/// - [`Error::InvalidCertificate`] if the [`Certificate`] couldn't be added
	///   as a certificate authority
	/// - [`Error::BindSocket`] if the socket couldn't be bound to the given
	///   `address`
	///
	/// # Panics
	/// If not called from inside the Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	pub fn new_client(ca: &Certificate) -> Result<Self> {
		let mut builder = Builder::new();
		let _ = builder.add_ca(ca)?;

		builder.build().map_err(|(error, _)| error)
	}

	/// Simplified version of creating a server. See [`Builder`] for more
	/// sophisticated configuration. Must be called from inside the Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// - [`Error::Certificate`] if the [`Certificate`] couldn't be parsed
	/// - [`Error::PrivateKey`] if the [`PrivateKey`] couldn't be parsed
	/// - [`Error::InvalidKeyPair`] if failed to pair the given [`Certificate`]
	///   and [`PrivateKey`]
	/// - [`Error::BindSocket`] if the socket couldn't be bound to the given
	///   `address`
	///
	/// # Panics
	/// If not called from inside the Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	pub fn new_server(
		port: u16,
		certificate: &Certificate,
		private_key: &PrivateKey,
	) -> Result<Self> {
		let mut builder = Builder::new();
		#[cfg(not(feature = "test"))]
		let _ = builder.set_address(([0; 8], port).into());
		// while testing always use the default loopback address
		#[cfg(feature = "test")]
		let _ = builder.set_address(([0, 0, 0, 0, 0, 0, 0, 1], port).into());
		let _ = builder.add_key_pair(certificate, private_key)?;

		builder.build().map_err(|(error, _)| error)
	}

	/// Handle incoming connections. Accessed through [`Stream`] of
	/// [`Endpoint`].
	async fn incoming(
		mut incoming: quinn::Incoming,
		sender: Sender<Result<Connection>>,
		mut shutdown: Receiver<()>,
	) {
		while let Some(connecting) = allochronic_util::select! {
			connecting: &mut incoming => connecting,
			_ : &mut shutdown => None,
		} {
			let connection = connecting
				.await
				.map(
					|NewConnection {
					     connection,
					     bi_streams,
					     ..
					 }| Connection::new(connection, bi_streams),
				)
				.map_err(Error::IncomingConnection);

			// if there is no receiver, it means that we dropped the last `Endpoint`
			if sender.send(connection).is_err() {
				break;
			}
		}
	}

	/// Establish a new [`Connection`] to a client. The `domain` validates
	/// the certificate.
	///
	/// # Errors
	/// - [`Error::Connect`] if no connection to the given `address` could be
	///   established
	/// - [`Error::Connecting`] if the connection to the given `address` failed
	pub async fn connect<D: AsRef<str>>(
		&self,
		address: SocketAddr,
		domain: D,
	) -> Result<Connection> {
		let connecting = self
			.endpoint
			.connect(&address, domain.as_ref())
			.map_err(Error::Connect)?;

		let NewConnection {
			connection,
			bi_streams,
			..
		} = connecting.await.map_err(Error::Connecting)?;

		Ok(Connection::new(connection, bi_streams))
	}

	/// Attempts to resolve the IP with the given domain name. This is done with
	/// the help of the [`trust_dns_resolver`] crate.
	///
	/// The following default are in play:
	/// - all system configurations are ignored
	/// - Cloudflare DNS is used as the name server
	/// - DNSSEC is used
	/// - DOH is used
	/// - IPv4 is preferred over IPv6
	///
	/// # Errors
	/// - [`Error::Resolve`] if the domain couldn't be resolved to an IP address
	/// - [`Error::Connect`] if no connection to the given `address` could be
	///   established
	/// - [`Error::Connecting`] if the connection to the given `address` failed
	#[cfg(feature = "dns")]
	pub async fn connect_with<S: AsRef<str>>(&self, port: u16, domain: S) -> Result<Connection> {
		let config = ResolverConfig::cloudflare_https();
		// `validate` enforces DNSSEC
		let opts = ResolverOpts {
			validate: true,
			..ResolverOpts::default()
		};

		// build the `Resolver`
		#[allow(box_pointers)]
		let resolver = TokioAsyncResolver::tokio(config, opts)
			.map_err(|error| Error::Resolve(Box::new(error)))?;
		// query the IP
		#[allow(box_pointers)]
		let ip = resolver
			.lookup_ip(domain.as_ref())
			.await
			.map_err(|error| Error::Resolve(Box::new(error)))?;

		// take the first IP found
		if let Some(ip) = ip.into_iter().next() {
			self.connect(SocketAddr::from((ip, port)), domain.as_ref())
				.await
		} else {
			Err(Error::NoIp)
		}
	}

	/// Get the local [`SocketAddr`] the underlying socket is bound to.
	///
	/// # Errors
	/// [`Error::LocalAddress`] if aquiring the local address failed.
	pub fn local_address(&self) -> Result<SocketAddr> {
		self.endpoint.local_addr().map_err(Error::LocalAddress)
	}

	/// Close all of this [`Endpoint`]'s [`Connection`]s immediately and cease
	/// accepting new [`Connection`]s.
	///
	/// To close an [`Endpoint`] gracefully use
	/// [`close_incoming`](Self::close_incoming),
	/// [`Sender::finish`](crate::Sender::finish) and
	/// [`wait_idle`](Self::wait_idle).
	///
	/// # Errors
	/// [`Error::AlreadyClosed`] if it was already closed.
	pub async fn close(&self) -> Result<()> {
		self.endpoint.close(VarInt::from_u32(0), &[]);
		(&self.task).await
	}

	/// Prevents any new incoming connections. Already incoming connections will
	/// finish first. This will always fail if the [`Endpoint`] wasn't started
	/// with a listener.
	///
	/// # Errors
	/// [`Error::AlreadyClosed`] if it was already closed.
	pub async fn close_incoming(&self) -> Result<()> {
		self.task.close(()).await
	}

	/// Wait for all [`Connection`]s to the [`Endpoint`] to be cleanly shut
	/// down. Does not close existing connections or cause incoming
	/// connections to be rejected. See
	/// [`close_incoming`](`Self::close_incoming`).
	pub async fn wait_idle(&self) {
		self.endpoint.wait_idle().await;
	}
}

impl Stream for Endpoint {
	type Item = Result<Connection>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		if self.receiver.is_terminated() {
			Poll::Ready(None)
		} else {
			self.receiver.poll_next_unpin(cx)
		}
	}
}

impl FusedStream for Endpoint {
	fn is_terminated(&self) -> bool {
		self.receiver.is_terminated()
	}
}

#[cfg(test)]
mod test {
	use anyhow::Result;

	use super::*;

	#[test]
	fn builder() {
		let _builder: Builder = Endpoint::builder();
	}

	#[tokio::test]
	async fn endpoint() -> Result<()> {
		use futures_util::StreamExt;

		let (certificate, private_key) = crate::generate_self_signed("test");

		let client = Endpoint::new_client(&certificate)?;
		let mut server = Endpoint::new_server(0, &certificate, &private_key)?;

		let _connection = client.connect(server.local_address()?, "test").await?;
		let _connection = server.next().await.expect("client dropped")?;

		Ok(())
	}

	#[tokio::test]
	async fn close() -> Result<()> {
		use futures_util::StreamExt;
		use quinn::ConnectionError;

		let (certificate, private_key) = crate::generate_self_signed("test");

		let client = Endpoint::new_client(&certificate)?;
		let mut server = Endpoint::new_server(0, &certificate, &private_key)?;
		let address = server.local_address()?;

		// `wait_idle` should never finish unless these `Connection`s are closed, which
		// they won't unless they are dropped or explicitly closed
		let _connection = client.connect(address, "test").await?;
		let _connection = server.next().await.expect("client dropped")?;

		// closing the client/server will close all connection immediately
		client.close().await?;
		assert!(matches!(client.close().await, Err(Error::AlreadyClosed)));
		server.close().await?;
		assert!(matches!(server.close().await, Err(Error::AlreadyClosed)));

		// connecting to a closed server shouldn't work
		assert!(matches!(
			client.connect(address, "test").await,
			Err(Error::Connecting(ConnectionError::LocallyClosed))
		));

		// waiting for a new connection on a closed server shouldn't work
		assert!(matches!(server.next().await, None));

		client.wait_idle().await;
		server.wait_idle().await;

		Ok(())
	}

	#[tokio::test]
	async fn close_incoming() -> Result<()> {
		use futures_util::StreamExt;
		use quinn::{ConnectionClose, ConnectionError};
		use quinn_proto::TransportErrorCode;

		let (certificate, private_key) = crate::generate_self_signed("test");

		let client = Endpoint::new_client(&certificate)?;
		let mut server = Endpoint::new_server(0, &certificate, &private_key)?;
		let address = server.local_address()?;

		// these `Connection`s should still work even if new incoming connections are
		// refused
		let client_connection = client.connect(address, "test").await?;
		let mut server_connection = server.next().await.expect("client dropped")?;

		// refuse new incoming connections
		client.close_incoming().await?;
		assert!(matches!(
			client.close_incoming().await,
			Err(Error::AlreadyClosed)
		));
		server.close_incoming().await?;
		assert!(matches!(
			server.close_incoming().await,
			Err(Error::AlreadyClosed)
		));

		// connecting to a server that refuses new `Connection`s shouldn't work
		assert!(matches!(
			client.connect(address, "test").await,
			Err(Error::Connecting(ConnectionError::ConnectionClosed(
				ConnectionClose {
					error_code: TransportErrorCode::CONNECTION_REFUSED,
					frame_type: None,
					reason: bytes,
				}
			))) if bytes.is_empty()
		));

		// waiting for a new connection on a server that refuses new `Connection`s
		// shouldn't work
		assert!(matches!(server.next().await, None));

		{
			let (sender, _) = client_connection.open_stream::<(), ()>().await?;
			sender.send(&())?;
			let _server_stream = server_connection
				.next()
				.await
				.expect("client dropped")
				.accept_stream::<()>();
		}

		drop(client_connection);
		drop(server_connection);

		client.wait_idle().await;
		server.wait_idle().await;

		Ok(())
	}

	#[tokio::test]
	async fn wait_idle() -> Result<()> {
		use futures_util::StreamExt;

		let (certificate, private_key) = crate::generate_self_signed("test");

		let client = Endpoint::new_client(&certificate)?;
		let mut server = Endpoint::new_server(0, &certificate, &private_key)?;

		// `wait_idle` will never finish unless the `Connection` closes, which happens
		// automatically when it's dropped
		{
			let _connection = client.connect(server.local_address()?, "test").await?;
			let _connection = server.next().await.expect("client dropped")?;
		}

		client.wait_idle().await;
		server.wait_idle().await;

		Ok(())
	}
}
