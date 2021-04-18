//! Starting point to create a QUIC enabled network socket.

mod builder;

use std::{
	fmt::{self, Debug, Formatter},
	net::{SocketAddr, ToSocketAddrs},
	pin::Pin,
	task::{Context, Poll},
};

use builder::Config;
pub use builder::{Builder, Dangerous, Store};
use flume::{r#async::RecvStream, Sender};
use futures_channel::oneshot::{self, Receiver};
use futures_util::{
	stream::{FusedStream, Stream},
	StreamExt,
};
use quinn::{ClientConfig, EndpointError, ServerConfig, VarInt};
use url::{Host, Url};

use super::Task;
use crate::{error, Certificate, Connecting, Error, KeyPair, Result};

/// Represents a socket using the QUIC protocol to communicate with peers.
/// Receives incoming [`Connection`](crate::Connection)s through [`Stream`].
#[derive(Clone)]
pub struct Endpoint {
	/// Initiate new connections or close socket.
	endpoint: quinn::Endpoint,
	/// Receiving new incoming connections.
	receiver: RecvStream<'static, Connecting>,
	/// Task handle handling new incoming connections.
	task: Task<()>,
	/// Persistent configuration to build new [`ClientConfig`]
	config: Config,
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

	/// Builds a new [`Endpoint`] from raw [`quinn`] types. Must be called from
	/// inside a Tokio [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// [`error::Builder`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// If not called from inside a Tokio [`Runtime`](tokio::runtime::Runtime).
	fn new(
		address: SocketAddr,
		client: ClientConfig,
		server: Option<ServerConfig>,
		config: Config,
	) -> Result<Self, error::Endpoint> {
		// configure endpoint for server and client
		let mut endpoint_builder = quinn::Endpoint::builder();
		let _ = endpoint_builder.default_client_config(client);

		// client don't need a server configuration
		let server = server.map_or(false, |server| {
			let _ = endpoint_builder.listen(server);
			true
		});

		// build endpoint
		let (endpoint, incoming) = endpoint_builder.bind(&address).map_err(|error| {
			error::Endpoint(match error {
				EndpointError::Socket(error) => error,
			})
		})?;

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
			config,
		})
	}

	/// Simplified version of creating a client. See [`Builder`] for more
	/// sophisticated configuration. Must be called from inside a Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Notes
	/// This configuration will not be able to receive new
	/// [`Connection`](crate::Connection)s.
	///
	/// # Errors
	/// [`error::Builder`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// If not called from inside a Tokio [`Runtime`](tokio::runtime::Runtime).
	pub fn new_client() -> Result<Self, error::Endpoint> {
		Builder::new()
			.build()
			.map_err(|error::Builder { error, .. }| error)
	}

	/// Simplified version of creating a server. See [`Builder`] for more
	/// sophisticated configuration. Must be called from inside a Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// [`error::Builder`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// - if the given [`KeyPair`] or [`Certificate`]s are invalid - can't
	///   happen if they were properly validated through [`KeyPair::from_parts`]
	///   or [`Certificate::from_der`]
	/// - if not called from inside a Tokio [`Runtime`](tokio::runtime::Runtime)
	pub fn new_server(port: u16, key_pair: KeyPair) -> Result<Self, error::Endpoint> {
		let mut builder = Builder::new();
		#[cfg(not(feature = "test"))]
		let _ = builder.set_address(([0; 8], port).into());
		// while testing always use the default loopback address
		#[cfg(feature = "test")]
		let _ = builder.set_address(([0, 0, 0, 0, 0, 0, 0, 1], port).into());
		let _ = builder.set_server_key_pair(Some(key_pair));

		builder
			.build()
			.map_err(|error::Builder { error, .. }| error)
	}

	/// Handle incoming connections. Accessed through [`Stream`] of
	/// [`Endpoint`].
	async fn incoming(
		mut incoming: quinn::Incoming,
		sender: Sender<Connecting>,
		mut shutdown: Receiver<()>,
	) {
		while let Some(connecting) = allochronic_util::select! {
			connecting: &mut incoming => connecting,
			_ : &mut shutdown => None,
		} {
			// if there is no receiver, it means that we dropped the last `Endpoint`
			if sender.send(Connecting::new(connecting)).is_err() {
				break;
			}
		}
	}

	/// Establishes a new [`Connection`](crate::Connection) to a server. The
	/// servers [`Certificate`] will be validated aggainst the root certificate
	/// store together with the domain.
	///
	/// Attempts to resolve the IP from the given URL. Uses
	/// [`trust-dns`](trust_dns_resolver) by default if the crate feature <span
	///   class="module-item stab portability"
	///   style="display: inline; border-radius: 3px; padding: 2px; font-size:
	/// 80%; line-height: 1.2;" ><code>trust-dns</code></span> is enabled.
	/// Otherwise [`ToSocketAddrs`] is used.
	///
	/// See [`Builder::disable_trust_dns`] for more control.
	///
	/// The following settings are used when using
	/// [`trust-dns`](trust_dns_resolver):
	/// - all system configurations are ignored
	/// - Cloudflare with DoH is used as the name server
	/// - DNSSEC is enabled
	/// - IPv6 is preferred over IPv4 if the bound socket is IPv6
	///
	/// # Errors
	/// - [`Error::ParseUrl`] if the URL couldn't be parsed
	/// - [`Error::Domain`] if the URL didn't contain a domain
	/// - [`Error::Port`] if the URL didn't contain a port
	/// - [`Error::ResolveTrustDns`] if the URL couldn't be resolved to an IP
	///   address with [`trust-dns`](trust_dns_resolver)
	/// - [`Error::ResolveStdDns`] if the URL couldn't be resolved to an IP
	///   address with [`ToSocketAddrs`]
	/// - [`Error::ConnectConfig`] if configuration needed to connect to a peer
	///   is faulty
	pub async fn connect<U: AsRef<str>>(&self, url: U) -> Result<Connecting> {
		let (address, domain) = self.resolve_domain(url).await?;

		Ok(Connecting::new(
			self.endpoint
				.connect(&address, &domain)
				.map_err(Error::ConnectConfig)?,
		))
	}

	/// Establishes a new [`Connection`](crate::Connection) to a server. The
	/// root certificate store will be ignored and the given [`Certificate`]
	/// will validate the server.
	///
	/// This method is intended for direct connection to a known server.
	/// Multiple domain names in the [`Certificate`] aren't supported.
	///
	/// See [`connect`](Self::connect) for more information on host name
	/// resolution.
	///
	/// # Errors
	/// - [`Error::MultipleDomains`] if multiple domains are used in this
	///   [`Certificate`]
	/// - [`Error::ParseUrl`] if the URL couldn't be parsed
	/// - [`Error::Domain`] if the URL didn't contain a domain
	/// - [`Error::Port`] if the URL didn't contain a port
	/// - [`Error::ResolveTrustDns`] if the URL couldn't be resolved to an IP
	///   address with [`trust-dns`](trust_dns_resolver)
	/// - [`Error::ResolveStdDns`] if the URL couldn't be resolved to an IP
	///   address with [`ToSocketAddrs`]
	/// - [`Error::ConnectConfig`] if configuration needed to connect to a peer
	///   is faulty
	///
	/// # Panics
	/// Panics if the given [`Certificate`] is invalid. Can't happen if the
	/// [`Certificate`] was properly validated through
	/// [`Certificate::from_der`].
	#[allow(clippy::unwrap_in_result)]
	pub async fn connect_pinned<U: AsRef<str>>(
		&self,
		url: U,
		server_certificate: &Certificate,
		client_key_pair: Option<KeyPair>,
	) -> Result<Connecting> {
		let mut domains = server_certificate.domains().into_iter();
		let domain = domains
			.next()
			.expect("`Certificate` contained no valid domains");

		if domains.next().is_some() {
			return Err(Error::MultipleDomains);
		}

		let (address, _) = self.resolve_domain(url).await?;

		let connecting = self
			.endpoint
			.connect_with(
				self.config
					.new_client(Some(server_certificate), Store::Empty, client_key_pair),
				&address,
				&domain,
			)
			.map_err(Error::ConnectConfig)?;

		Ok(Connecting::new(connecting))
	}

	/// Resolve the IP from the given domain. See [`connect`](Self::connect) for
	/// more details.
	///
	/// # Errors
	/// - [`Error::ParseUrl`] if the URL couldn't be parsed
	/// - [`Error::Domain`] if the URL didn't contain a domain
	/// - [`Error::Port`] if the URL didn't contain a port
	/// - [`Error::ResolveTrustDns`] if the URL couldn't be resolved to an IP
	///   address with [`trust-dns`](trust_dns_resolver)
	/// - [`Error::ResolveStdDns`] if the URL couldn't be resolved to an IP
	///   address with [`ToSocketAddrs`]
	async fn resolve_domain(&self, url: impl AsRef<str>) -> Result<(SocketAddr, String)> {
		let url = Url::parse(url.as_ref()).map_err(Error::ParseUrl)?;
		// url removes known default ports, we don't actually want to accept known
		// schemes, but this is proabably not intended behaviour
		let port = url.port_or_known_default().ok_or(Error::Port)?;
		let domain = url.host_str().ok_or(Error::Domain)?;
		// url doesn't parse IP addresses unless the schema is known, which doesn't
		// work for "quic://" for example
		let domain = match Host::parse(domain).map_err(Error::ParseUrl)? {
			Host::Domain(domain) => domain,
			Host::Ipv4(ip) => return Ok((SocketAddr::from((ip, port)), ip.to_string())),
			Host::Ipv6(ip) => return Ok((SocketAddr::from((ip, port)), ip.to_string())),
		};

		#[cfg(feature = "trust-dns")]
		if self.config.trust_dns() {
			use trust_dns_resolver::{
				config::{LookupIpStrategy, ResolverConfig, ResolverOpts},
				TokioAsyncResolver,
			};

			// ip strategy depends on the current socket
			let ip_strategy = if let Ok(true) = self.local_address().map(|socket| socket.is_ipv6())
			{
				LookupIpStrategy::Ipv6thenIpv4
			} else {
				LookupIpStrategy::Ipv4Only
			};

			// build `Resolver` options
			let opts = ResolverOpts {
				ip_strategy,
				use_hosts_file: false,
				validate: true,
				..ResolverOpts::default()
			};

			// build the `Resolver`
			#[allow(box_pointers)]
			let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), opts)
				.map_err(|error| Error::ResolveTrustDns(Box::new(error)))?;
			// query the IP
			#[allow(box_pointers)]
			let ip = resolver
				.lookup_ip(domain.clone())
				.await
				.map_err(|error| Error::ResolveTrustDns(Box::new(error)))?;

			// take the first IP found
			let ip = ip.into_iter().next().ok_or(Error::NoIp)?;

			return Ok((SocketAddr::from((ip, port)), domain));
		}

		// TODO: configure executor
		let address = {
			// `ToSocketAddrs` needs a port
			let domain = format!("{}:{}", domain, port);
			tokio::task::spawn_blocking(move || {
				domain
					.to_socket_addrs()
					.map_err(Error::ResolveStdDns)?
					.next()
					.ok_or(Error::NoIp)
			})
			.await
			.expect("Resolving domain panicked")?
		};

		Ok((address, domain))
	}

	/// Get the local [`SocketAddr`] the underlying socket is bound to.
	///
	/// # Errors
	/// [`Error::LocalAddress`] if aquiring the local address failed.
	pub fn local_address(&self) -> Result<SocketAddr> {
		self.endpoint.local_addr().map_err(Error::LocalAddress)
	}

	/// Close all of this [`Endpoint`]'s [`Connection`](crate::Connection)s
	/// immediately and cease accepting new [`Connection`](crate::Connection)s.
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
		// we only want to wait until it's actually closed, it might already be closed
		// by `close_incoming` or by starting as a client
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

	/// Wait for all [`Connection`](crate::Connection)s to the [`Endpoint`] to
	/// be cleanly shut down. Does not close existing connections or cause
	/// incoming connections to be rejected. See
	/// [`close_incoming`](`Self::close_incoming`).
	pub async fn wait_idle(&self) {
		self.endpoint.wait_idle().await;
	}
}

impl Stream for Endpoint {
	type Item = Connecting;

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
	use futures_util::StreamExt;
	use quinn::{ConnectionClose, ConnectionError};
	use quinn_proto::TransportErrorCode;

	use super::*;
	use crate::KeyPair;

	#[test]
	fn builder() {
		let _builder: Builder = Endpoint::builder();
	}

	#[tokio::test]
	async fn endpoint() -> Result<()> {
		let key_pair = KeyPair::new_self_signed("test");

		let client = Endpoint::new_client()?;
		let mut server = Endpoint::new_server(0, key_pair.clone())?;

		let _connection = client
			.connect_pinned(
				format!("quic://{}", server.local_address()?),
				key_pair.certificate(),
				None,
			)
			.await?
			.accept::<()>()
			.await?;
		let _connection = server
			.next()
			.await
			.expect("client dropped")
			.accept::<()>()
			.await?;

		Ok(())
	}

	#[tokio::test]
	async fn close() -> Result<()> {
		let key_pair = KeyPair::new_self_signed("test");

		let client = Endpoint::new_client()?;
		let mut server = Endpoint::new_server(0, key_pair.clone())?;
		let address = format!("quic://{}", server.local_address()?);

		// `wait_idle` should never finish unless these `Connection`s are closed, which
		// they won't unless they are dropped or explicitly closed
		let _connection = client
			.connect_pinned(&address, key_pair.certificate(), None)
			.await?
			.accept::<()>()
			.await?;
		let _connection = server
			.next()
			.await
			.expect("client dropped")
			.accept::<()>()
			.await?;

		// closing the client/server will close all connection immediately
		assert!(matches!(client.close().await, Err(Error::AlreadyClosed)));
		server.close().await?;

		// connecting to a closed server shouldn't work
		assert!(matches!(
			client
				.connect_pinned(address, key_pair.certificate(), None)
				.await?
				.accept::<()>()
				.await,
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
		let key_pair = KeyPair::new_self_signed("test");

		let client = Endpoint::new_client()?;
		let mut server = Endpoint::new_server(0, key_pair.clone())?;
		let address = format!("quic://{}", server.local_address()?);

		// these `Connection`s should still work even if new incoming connections are
		// refused
		let client_connection = client
			.connect_pinned(&address, key_pair.certificate(), None)
			.await?
			.accept::<()>()
			.await?;
		let mut server_connection = server
			.next()
			.await
			.expect("client dropped")
			.accept::<()>()
			.await?;

		// refuse new incoming connections
		// client never accepts incoming connections
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
		let result = client
			.connect_pinned(address, key_pair.certificate(), None)
			.await?
			.accept::<()>()
			.await;
		assert!(matches!(
			result,
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
			let (sender, _) = client_connection.open_stream::<(), ()>(&()).await?;
			let _server_stream = server_connection
				.next()
				.await
				.expect("client dropped")
				.accept::<(), ()>();
			sender.finish().await?;
		}

		drop(client_connection);
		drop(server_connection);

		client.wait_idle().await;
		server.wait_idle().await;

		Ok(())
	}

	#[tokio::test]
	async fn wait_idle() -> Result<()> {
		let key_pair = KeyPair::new_self_signed("test");

		let client = Endpoint::new_client()?;
		let mut server = Endpoint::new_server(0, key_pair.clone())?;

		// `wait_idle` will never finish unless the `Connection` closes, which happens
		// automatically when it's dropped
		{
			let _connection = client
				.connect_pinned(
					format!("quic://{}", server.local_address()?),
					key_pair.certificate(),
					None,
				)
				.await?
				.accept::<()>()
				.await?;
			let _connection = server
				.next()
				.await
				.expect("client dropped")
				.accept::<()>()
				.await?;
		}

		client.wait_idle().await;
		server.wait_idle().await;

		Ok(())
	}
}
