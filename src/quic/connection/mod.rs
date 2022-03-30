//! [`Connection`]s hold a connection to a peer in an
//! [`Endpoint`](crate::Endpoint).
//!
//!
//! A single [`Connection`] can have multiple streams, streams consist of a
//! [`Sender`] and [`Receiver`], which can send and receive messages on that
//! stream.
//!
//! You can use [`open_stream`](Connection::open_stream) to open a stream.

mod connecting;
mod incoming;
mod receiver;
mod receiver_stream;
mod sender;

use std::{
	fmt::{self, Debug, Formatter},
	marker::PhantomData,
	net::SocketAddr,
	pin::Pin,
	task::{Context, Poll},
};

pub use connecting::Connecting;
use flume::r#async::RecvStream;
use futures_util::{
	stream::{self, FusedStream},
	StreamExt,
};
pub use incoming::Incoming;
use pin_project::pin_project;
use quinn::{crypto::rustls::HandshakeData, IncomingBiStreams, VarInt};
pub use receiver::Receiver;
use receiver_stream::ReceiverStream;
pub use sender::Sender;
use stream::Stream;
use transmog::{Format, OwnedDeserializer};

use super::Task;
use crate::{
	error::{self, SerializationError},
	CertificateChain,
};

/// Represents an open connection. Receives [`Incoming`] through [`Stream`].
#[pin_project]
#[derive(Clone)]
pub struct Connection<T, F>
where
	T: Send + 'static,
	F: OwnedDeserializer<T>,
{
	/// Initiate new connections or close socket.
	connection: quinn::Connection,
	/// Receive incoming streams.
	receiver:
		RecvStream<'static, Result<(quinn::SendStream, quinn::RecvStream), error::Connection>>,
	/// [`Task`] handling new incoming streams.
	task: Task<()>,
	/// Serialization foramt.
	format: F,
	/// Type for type negotiation for new streams.
	types: PhantomData<T>,
}

impl<T, F> Debug for Connection<T, F>
where
	T: Send + 'static,
	F: OwnedDeserializer<T>,
{
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Connection")
			.field("connection", &self.connection)
			.field("receiver", &"RecvStream")
			.field("task", &self.task)
			.field("types", &self.types)
			.finish()
	}
}

impl<T, F> Connection<T, F>
where
	T: Send + 'static,
	F: OwnedDeserializer<T> + Clone,
	F::Error: SerializationError,
{
	/// Builds a new [`Connection`] from raw [`quinn`] types.
	#[allow(clippy::mut_mut)] // futures_util::select_biased internal usage
	pub(super) fn new(
		connection: quinn::Connection,
		bi_streams: IncomingBiStreams,
		format: F,
	) -> Self {
		// channels for passing down new `Incoming` `Connection`s
		let (sender, receiver) = flume::unbounded();
		let receiver = receiver.into_stream();

		// `Task` handling incoming streams
		let task = Task::new(|mut shutdown| async move {
			let mut bi_streams = bi_streams.fuse();
			while let Some(connecting) = futures_util::select_biased! {
				connecting = bi_streams.next() => connecting,
				_ = shutdown => None,
				complete => None,
			} {
				let incoming = connecting.map_err(error::Connection);

				if sender.send(incoming).is_err() {
					// if there is no receiver, it means that we dropped the last
					// `Connection`
					break;
				}
			}
		});

		Self {
			connection,
			receiver,
			task,
			format,
			types: PhantomData,
		}
	}

	/// Open a stream on this [`Connection`], allowing to send data back and
	/// forth.
	///
	/// Use `S` and `R` to define which type this stream is sending and
	/// receiving and `type` to send this information to the receiver.
	///
	/// # Errors
	/// - [`error::Stream::Open`] if opening a stream failed
	/// - [`error::Stream::Sender`] if sending the type information to the peer
	///   failed, see [`error::Sender`] for more details
	pub async fn open_stream<S: Send + 'static, R: Send + 'static>(
		&self,
		r#type: &T,
	) -> Result<(Sender<S, F>, Receiver<R>), error::Stream>
	where
		F: OwnedDeserializer<R> + Format<'static, S> + Format<'static, T> + 'static,
		<F as Format<'static, R>>::Error: SerializationError,
		<F as Format<'static, S>>::Error: SerializationError,
	{
		let (sender, receiver) = self.connection.open_bi().await?;

		let sender = Sender::new(sender, self.format.clone());
		let receiver = Receiver::new(ReceiverStream::new(receiver, self.format.clone()));

		sender.send_any(r#type, &self.format)?;

		Ok((sender, receiver))
	}

	/// Open a stream on this [`Connection`], allowing to send data back and
	/// forth using another serialization format.
	///
	/// Use `S` and `R` to define which type this stream is sending and
	/// receiving and `type` to send this information to the receiver. `format`
	/// will be used for serializing `S` and `R`.
	///
	/// # Errors
	/// - [`error::Stream::Open`] if opening a stream failed
	/// - [`error::Stream::Sender`] if sending the type information to the peer
	///   failed, see [`error::Sender`] for more details
	pub async fn open_stream_with_format<S: Send + 'static, R: Send + 'static, NewFormat>(
		&self,
		r#type: &T,
		format: NewFormat,
	) -> Result<(Sender<S, NewFormat>, Receiver<R>), error::Stream>
	where
		NewFormat: OwnedDeserializer<R> + Format<'static, S> + Clone + 'static,
		<NewFormat as Format<'static, R>>::Error: SerializationError,
		<NewFormat as Format<'static, S>>::Error: SerializationError,
	{
		let (sender, receiver) = self.connection.open_bi().await?;

		let sender = Sender::new(sender, format.clone());
		let receiver = Receiver::new(ReceiverStream::new(receiver, format));

		sender.send_any(r#type, &self.format)?;

		Ok((sender, receiver))
	}

	/// The negotiated application protocol. See
	/// [`Builder::set_protocols`](crate::Builder::set_protocols).
	#[must_use]
	pub fn protocol(&self) -> Option<Vec<u8>> {
		self.connection.handshake_data().and_then(|data| {
			data.downcast_ref::<HandshakeData>()
				.and_then(|data| data.protocol.clone())
		})
	}

	/// Get the peer's [`CertificateChain`], if available.
	#[must_use]
	pub fn peer_identity(&self) -> Option<CertificateChain> {
		self.connection.peer_identity().and_then(|cert| {
			cert.downcast_ref::<Vec<rustls::Certificate>>()
				.map(|certs| CertificateChain::from_rustls(certs))
		})
	}

	/// The peer's address. Clients may change addresses at will, e.g. when
	/// switching to a cellular internet connection.
	#[must_use]
	pub fn remote_address(&self) -> SocketAddr {
		self.connection.remote_address()
	}

	/// Prevents any new incoming streams. Already incoming streams will
	/// finish first.
	///
	/// # Errors
	/// [`error::AlreadyClosed`] if it was already closed.
	pub async fn close_incoming(&self) -> Result<(), error::AlreadyClosed> {
		self.task.close(()).await
	}

	/// Close the [`Connection`] immediately.
	///
	/// To close a [`Connection`] gracefully use [`Sender::finish`], the
	/// [`Receiver`] can't be gracefully closed from the receiving end.
	///
	/// # Errors
	/// [`error::AlreadyClosed`] if it was already closed.
	pub async fn close(&self) -> Result<(), error::AlreadyClosed> {
		self.connection.close(VarInt::from_u32(0), &[]);
		(&self.task).await
	}
}

impl<T, F> Stream for Connection<T, F>
where
	T: Send + 'static,
	F: OwnedDeserializer<T> + Clone,
	F::Error: SerializationError,
{
	type Item = Result<Incoming<T, F>, error::Connection>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		if self.receiver.is_terminated() {
			Poll::Ready(None)
		} else {
			self.receiver
				.poll_next_unpin(cx)
				.map_ok(|(sender, receiver)| Incoming::new(sender, receiver, self.format.clone()))
		}
	}
}

impl<T, F> FusedStream for Connection<T, F>
where
	T: Send + 'static,
	F: OwnedDeserializer<T> + Clone,
	F::Error: SerializationError,
{
	fn is_terminated(&self) -> bool {
		self.receiver.is_terminated()
	}
}
