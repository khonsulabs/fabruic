//! Starting point to create a QUIC enabled network socket.

mod builder;

use std::{
	fmt::{self, Debug, Formatter},
	io::Error,
	net::{SocketAddr, ToSocketAddrs},
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use builder::Config;
pub use builder::{Builder, Dangerous, Store};
use flume::{r#async::RecvStream, Sender};
use futures_channel::oneshot::Receiver;
use futures_util::{
	stream::{FusedStream, Stream},
	StreamExt,
};
use quinn::{ClientConfig, EndpointError, ServerConfig, VarInt};
use url::{Host, Url};

use super::Task;
use crate::{error, Certificate, Connecting, KeyPair};

/// Represents a socket using the QUIC protocol to communicate with peers.
///
/// # Stream
/// Receives incoming [`Connection`](crate::Connection)s through [`Stream`].
#[must_use = "doesn't do anything unless polled to receive `Connection`s or opening new ones with \
              `Endpoint::connect`"]
#[derive(Clone)]
pub struct Endpoint {
	/// Initiate new [`Connection`](crate::Connection)s or close [`Endpoint`].
	endpoint: quinn::Endpoint,
	/// Receiving new incoming [`Connection`](crate::Connection)s.
	receiver: RecvStream<'static, Connecting>,
	/// Task handle handling new incoming connections.
	task: Task<()>,
	/// Persistent configuration from [`Builder`] to build new [`ClientConfig`]s
	/// and [`trust-dns`](trust_dns_resolver) queries.
	config: Arc<Config>,
}

impl Debug for Endpoint {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Server")
			.field("endpoint", &self.endpoint)
			.field("receiver", &"RecvStream")
			.field("task", &self.task)
			.field("config", &self.config)
			.finish()
	}
}

impl Endpoint {
	/// Builds a new [`Builder`]. See [`Builder`] methods for defaults.
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::Endpoint;
	///
	/// let endpoint = Endpoint::builder().build()?;
	/// # Ok(()) }
	/// ```
	pub fn builder() -> Builder {
		Builder::new()
	}

	/// Builds a new [`Endpoint`] from raw [`quinn`] types. Must be called from
	/// inside a Tokio [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// [`std::io::Error`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// If not called from inside a Tokio [`Runtime`](tokio::runtime::Runtime).
	fn new(
		address: SocketAddr,
		client: ClientConfig,
		server: Option<ServerConfig>,
		config: Config,
	) -> Result<Self, Error> {
		// configure endpoint for server and client
		let mut endpoint_builder = quinn::Endpoint::builder();
		let _ = endpoint_builder.default_client_config(client);

		// server configuration is optional
		let server = server.map_or(false, |server| {
			let _ = endpoint_builder.listen(server);
			true
		});

		// build endpoint
		let (endpoint, incoming) =
			endpoint_builder
				.bind(&address)
				.map_err(|error| match error {
					EndpointError::Socket(error) => error,
				})?;

		// create channels that will receive incoming `Connection`s
		let (sender, receiver) = flume::unbounded();
		let receiver = receiver.into_stream();

		// only servers need to deal with incoming connections
		let task = if server {
			// spawn task handling incoming `Connection`s
			Task::new(|shutdown| Self::incoming(incoming, sender, shutdown))
		} else {
			Task::empty()
		};

		Ok(Self {
			endpoint,
			receiver,
			task,
			config: Arc::new(config),
		})
	}

	/// Simplified version of creating a client. See [`Builder`] for more
	/// sophisticated configuration options. Must be called from inside a Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Notes
	/// This configuration will not be able to receive incoming
	/// [`Connection`](crate::Connection)s.
	///
	/// # Errors
	/// [`std::io::Error`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// If not called from inside a Tokio [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::Endpoint;
	///
	/// let endpoint = Endpoint::new_client()?;
	/// # Ok(()) }
	/// ```
	pub fn new_client() -> Result<Self, Error> {
		Builder::new()
			.build()
			.map_err(|error::Builder { error, .. }| error)
	}

	/// Simplified version of creating a server. See [`Builder`] for more
	/// sophisticated configuration options. Must be called from inside a Tokio
	/// [`Runtime`](tokio::runtime::Runtime).
	///
	/// # Errors
	/// [`std::io::Error`] if the socket couldn't be bound to the given
	/// `address`.
	///
	/// # Panics
	/// - if the given [`KeyPair`] is invalid - can't happen if properly
	///   validated through [`KeyPair::from_parts`]
	/// - if not called from inside a Tokio [`Runtime`](tokio::runtime::Runtime)
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::{Endpoint, KeyPair};
	///
	/// let endpoint = Endpoint::new_server(0, KeyPair::new_self_signed("self-signed"))?;
	/// # Ok(()) }
	/// ```
	pub fn new_server(port: u16, key_pair: KeyPair) -> Result<Self, Error> {
		let mut builder = Builder::new();
		#[cfg(not(feature = "test"))]
		let _ = builder.set_address(([0; 8], port).into());
		// while testing always use the default loopback address
		#[cfg(feature = "test")]
		builder.set_address(([0, 0, 0, 0, 0, 0, 0, 1], port).into());
		builder.set_server_key_pair(Some(key_pair));

		builder
			.build()
			.map_err(|error::Builder { error, .. }| error)
	}

	/// Handle incoming connections. Accessed through [`Stream`] in
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
	/// store and the domain in the URL.
	///
	/// Attempts to resolve the IP from the given URL. Uses
	/// [`trust-dns`](trust_dns_resolver) by default if the crate feature <span
	///   class="module-item stab portability"
	///   style="display: inline; border-radius: 3px; padding: 2px; font-size:
	/// 80%; line-height: 1.2;" ><code>trust-dns</code></span> is enabled.
	/// Otherwise [`ToSocketAddrs`] is used.
	///
	/// See [`Builder::set_trust_dns`] or [`Builder::disable_trust_dns`] for
	/// more control.
	///
	/// # Notes
	/// The following settings are used when using
	/// [`trust-dns`](trust_dns_resolver):
	/// - all system configurations are ignored, see [`Builder::set_hosts_file`]
	/// - Cloudflare with DoH is used as the name server
	/// - DNSSEC is enabled, see [`Builder::set_dnssec`]
	/// - IPv6 is preferred over IPv4 if the bound socket is IPv6
	///
	/// # Errors
	/// - [`error::Connect::ParseUrl`] if the URL couldn't be parsed
	/// - [`error::Connect::Domain`] if the URL didn't contain a domain
	/// - [`error::Connect::Port`] if the URL didn't contain a port
	/// - [`error::Connect::ParseDomain`] if the domain couldn't be parsed
	/// - [`error::Connect::TrustDns`] if the URL couldn't be resolved to an IP
	///   address with [`trust-dns`](trust_dns_resolver)
	/// - [`error::Connect::StdDns`] if the URL couldn't be resolved to an IP
	///   address with [`ToSocketAddrs`]
	/// - [`error::Connect::NoIp`] if no IP address was found for that domain
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::Endpoint;
	///
	/// let endpoint = Endpoint::new_client()?;
	/// // not going to actually work because `localhost` can't have a valid certificate
	/// let connecting = endpoint.connect("quic://localhost:443").await?;
	/// # Ok(()) }
	/// ```
	pub async fn connect<U: AsRef<str>>(&self, url: U) -> Result<Connecting, error::Connect> {
		let (address, domain) = self.resolve_domain(url).await?;

		Ok(Connecting::new(
			self.endpoint
				.connect(&address, &domain)
				.map_err(error::Connect::Config)?,
		))
	}

	/// Establishes a new [`Connection`](crate::Connection) to a server.
	///
	/// See [`connect`](Self::connect) for more information on host name
	/// resolution.
	///
	/// # Notes
	/// The root certificate store will be ignored and the given [`Certificate`]
	/// will validate the server.
	///
	/// A client certificate [`KeyPair`] set with
	/// [`Builder::set_client_key_pair`] will be ignored, use `client_key_pair`
	/// to add a client certificate to this connection.
	///
	/// This method is intended for direct connection to a known server, the
	/// domain name in the URL is not checked against the [`Certificate`].
	/// Multiple domain names in the [`Certificate`] aren't supported.
	///
	/// # Errors
	/// - [`error::Connect::MultipleDomains`] if multiple domains are present in
	///   the [`Certificate`], which isn't supported
	/// - [`error::Connect::ParseUrl`] if the URL couldn't be parsed
	/// - [`error::Connect::Domain`] if the URL didn't contain a domain
	/// - [`error::Connect::Port`] if the URL didn't contain a port
	/// - [`error::Connect::ParseDomain`] if the domain couldn't be parsed
	/// - [`error::Connect::TrustDns`] if the URL couldn't be resolved to an IP
	///   address with [`trust-dns`](trust_dns_resolver)
	/// - [`error::Connect::StdDns`] if the URL couldn't be resolved to an IP
	///   address with [`ToSocketAddrs`]
	/// - [`error::Connect::NoIp`] if no IP address was found for that domain
	///
	/// # Panics
	/// Panics if the given [`Certificate`] or [`KeyPair`] are invalid. Can't
	/// happen if they were properly validated through [`Certificate::from_der`]
	/// or [`KeyPair::from_parts`].
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::Endpoint;
	///
	/// let endpoint = Endpoint::new_client()?;
	/// // the server certificate has to be imported from somewhere else
	/// # let (server_certificate, _) = fabruic::KeyPair::new_self_signed("localhost").into_parts();
	/// # let server_certificate = server_certificate.into_end_entity_certificate();
	/// let connecting = endpoint
	/// 	.connect_pinned("quic://localhost:443", &server_certificate, None)
	/// 	.await?;
	/// # Ok(()) }
	/// ```
	#[allow(clippy::unwrap_in_result)]
	pub async fn connect_pinned<U: AsRef<str>>(
		&self,
		url: U,
		server_certificate: &Certificate,
		client_key_pair: Option<KeyPair>,
	) -> Result<Connecting, error::Connect> {
		// check `Certificate` for a domain
		let mut domains = server_certificate.domains().into_iter();
		let domain = domains
			.next()
			.expect("`Certificate` contained no valid domains");

		// multiple domains aren't supported
		if domains.next().is_some() {
			return Err(error::Connect::MultipleDomains);
		}

		// resolve URL
		let (address, _) = self.resolve_domain(url).await?;

		// build client configuration
		let client =
			self.config
				.new_client(Some(server_certificate), Store::Empty, client_key_pair);

		// connet
		let connecting = self
			.endpoint
			.connect_with(client, &address, &domain)
			.map_err(error::Connect::Config)?;

		Ok(Connecting::new(connecting))
	}

	/// Resolve the IP from the given domain. See [`connect`](Self::connect) for
	/// more details.
	///
	/// # Errors
	/// - [`error::Connect::ParseUrl`] if the URL couldn't be parsed
	/// - [`error::Connect::Domain`] if the URL didn't contain a domain
	/// - [`error::Connect::Port`] if the URL didn't contain a port
	/// - [`error::Connect::ParseDomain`] if the domain couldn't be parsed
	/// - [`error::Connect::TrustDns`] if the URL couldn't be resolved to an IP
	///   address with [`trust-dns`](trust_dns_resolver)
	/// - [`error::Connect::StdDns`] if the URL couldn't be resolved to an IP
	///   address with [`ToSocketAddrs`]
	/// - [`error::Connect::NoIp`] if no IP address was found for that domain
	async fn resolve_domain(
		&self,
		url: impl AsRef<str>,
	) -> Result<(SocketAddr, String), error::Connect> {
		let url = Url::parse(url.as_ref()).map_err(error::Connect::ParseUrl)?;
		// url removes known default ports, we don't actually want to accept known
		// scheme's, but this is probably not intended behaviour
		let port = url.port_or_known_default().ok_or(error::Connect::Port)?;
		let domain = url.host_str().ok_or(error::Connect::Domain)?;
		// url doesn't parse IP addresses unless the schema is known, which doesn't
		// work for "quic://" for example
		let domain = match Host::parse(domain).map_err(error::Connect::ParseDomain)? {
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

			// IP strategy depends on the current socket
			let ip_strategy = if let Ok(true) = self.local_address().map(|socket| socket.is_ipv6())
			{
				LookupIpStrategy::Ipv6thenIpv4
			} else {
				LookupIpStrategy::Ipv4Only
			};

			// build `Resolver` options
			let opts = ResolverOpts {
				ip_strategy,
				use_hosts_file: self.config.hosts_file(),
				validate: self.config.dnssec(),
				..ResolverOpts::default()
			};

			// build the `Resolver`
			let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_https(), opts)
				.map_err(Box::new)?;
			// query the IP
			let ip = resolver.lookup_ip(domain.clone()).await.map_err(Box::new)?;

			// take the first IP found
			// TODO: retry connection on other found IPs
			let ip = ip.into_iter().next().ok_or(error::Connect::NoIp)?;

			return Ok((SocketAddr::from((ip, port)), domain));
		}

		// TODO: configurable executor
		let address = {
			// `ToSocketAddrs` needs a port
			let domain = format!("{}:{}", domain, port);
			tokio::task::spawn_blocking(move || {
				domain.to_socket_addrs()?.next().ok_or(error::Connect::NoIp)
			})
			.await
			.expect("Resolving domain panicked")?
		};

		Ok((address, domain))
	}

	/// Get the local [`SocketAddr`] the underlying socket is bound to.
	///
	/// # Errors
	/// [`std::io::Error`] if aquiring the local address failed.
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::Endpoint;
	///
	/// let endpoint = Endpoint::new_client()?;
	/// assert!(endpoint.local_address().is_ok());
	/// # Ok(()) }
	/// ```
	pub fn local_address(&self) -> Result<SocketAddr, Error> {
		self.endpoint.local_addr()
	}

	/// Close all of this [`Endpoint`]'s [`Connection`](crate::Connection)s
	/// immediately and cease accepting new [`Connection`](crate::Connection)s.
	///
	/// To close an [`Endpoint`] gracefully use
	/// [`close_incoming`](Self::close_incoming),
	/// [`Sender::finish`](crate::Sender::finish) and
	/// [`wait_idle`](Self::wait_idle).
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::Endpoint;
	///
	/// let endpoint = Endpoint::new_client()?;
	/// endpoint.close();
	/// # Ok(()) }
	/// ```
	pub async fn close(&self) {
		self.endpoint.close(VarInt::from_u32(0), &[]);
		// we only want to wait until it's actually closed, it might already be closed
		// by `close_incoming` or by starting as a client
		let _result = (&self.task).await;
	}

	/// Prevents any new incoming connections. Already incoming connections will
	/// finish first. This will always return [`error::AlreadyClosed`] if the
	/// [`Endpoint`] wasn't started with a listener.
	///
	/// See [`Builder::set_server_key_pair`].
	///
	/// # Errors
	/// [`error::AlreadyClosed`] if it was already closed.
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::{Endpoint, KeyPair};
	///
	/// let endpoint = Endpoint::new_server(0, KeyPair::new_self_signed("test"))?;
	/// assert!(endpoint.close_incoming().await.is_ok());
	/// # Ok(()) }
	/// ```
	pub async fn close_incoming(&self) -> Result<(), error::AlreadyClosed> {
		self.task.close(()).await
	}

	/// Wait for all [`Connection`](crate::Connection)s to the [`Endpoint`] to
	/// be cleanly shut down. Does not close existing connections or cause
	/// incoming connections to be rejected. See
	/// [`close_incoming`](`Self::close_incoming`).
	///
	/// # Examples
	/// ```
	/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
	/// use fabruic::Endpoint;
	///
	/// let endpoint = Endpoint::new_client()?;
	/// endpoint.wait_idle().await;
	/// # Ok(()) }
	/// ```
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
	use std::str::FromStr;

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
				key_pair.end_entity_certificate(),
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
	async fn port() -> Result<()> {
		let client = Endpoint::new_client()?;

		assert!(matches!(
			client.resolve_domain("https://localhost").await,
			Ok((address, domain))
			if address == SocketAddr::from_str("[::1]:443")? && domain == "localhost"
		));

		assert!(matches!(
			client.resolve_domain("quic://localhost").await,
			Err(error::Connect::Port)
		));

		assert!(matches!(
			client.resolve_domain("quic://localhost:443").await,
			Ok((address, domain))
			if address == SocketAddr::from_str("[::1]:443")? && domain == "localhost"
		));

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
			.connect_pinned(&address, key_pair.end_entity_certificate(), None)
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
		client.close().await;
		server.close().await;

		// connecting to a closed server shouldn't work
		assert!(matches!(
			client
				.connect_pinned(address, key_pair.end_entity_certificate(), None)
				.await?
				.accept::<()>()
				.await,
			Err(error::Connecting(ConnectionError::LocallyClosed))
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
			.connect_pinned(&address, key_pair.end_entity_certificate(), None)
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
			Err(error::AlreadyClosed)
		));
		server.close_incoming().await?;
		assert!(matches!(
			server.close_incoming().await,
			Err(error::AlreadyClosed)
		));

		// connecting to a server that refuses new `Connection`s shouldn't work
		let result = client
			.connect_pinned(address, key_pair.end_entity_certificate(), None)
			.await?
			.accept::<()>()
			.await;
		assert!(matches!(
			result,
			Err(error::Connecting(ConnectionError::ConnectionClosed(
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
				.expect("client dropped")?
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
					key_pair.end_entity_certificate(),
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
