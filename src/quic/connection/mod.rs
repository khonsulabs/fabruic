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
	future::Future,
	marker::PhantomData,
	net::SocketAddr,
	pin::{pin, Pin},
	task::{Context, Poll},
};

pub use connecting::Connecting;
use futures_channel::oneshot;
use futures_util::{
	stream::{self, FusedStream},
	FutureExt, StreamExt,
};
pub use incoming::Incoming;
use pin_project::pin_project;
use quinn::{crypto::rustls::HandshakeData, AcceptBi, RecvStream, SendStream, VarInt};
pub use receiver::Receiver;
use receiver_stream::ReceiverStream;
pub use sender::Sender;
use serde::{de::DeserializeOwned, Serialize};
use stream::Stream;

use super::Task;
use crate::{error, CertificateChain};

/// Represents an open connection. Receives [`Incoming`] through [`Stream`].
#[pin_project]
#[derive(Clone)]
pub struct Connection<T: DeserializeOwned + Serialize + Send + 'static> {
	/// Initiate new connections or close socket.
	connection: quinn::Connection,
	/// Receive incoming streams.
	receiver:
		flume::r#async::RecvStream<'static, Result<(SendStream, RecvStream), error::Connection>>,
	/// [`Task`] handling new incoming streams.
	task: Task<()>,
	/// Type for type negotiation for new streams.
	types: PhantomData<T>,
}

impl<T: DeserializeOwned + Serialize + Send + 'static> Debug for Connection<T> {
	fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("Connection")
			.field("connection", &self.connection)
			.field("receiver", &"RecvStream")
			.field("task", &self.task)
			.field("types", &self.types)
			.finish()
	}
}

impl<T: DeserializeOwned + Serialize + Send + 'static> Connection<T> {
	/// Builds a new [`Connection`] from raw [`quinn`] types.
	pub(super) fn new(connection: quinn::Connection) -> Self {
		// channels for passing down new `Incoming` `Connection`s
		let (sender, receiver) = flume::unbounded();
		let receiver = receiver.into_stream();

		// `Task` handling incoming streams
		let task = Task::new(|shutdown| {
			let connection = connection.clone();
			async move {
				IncomingStreams {
					connection: &connection,
					accept: None,
					shutdown,
					sender,
					complete: false,
				}
				.await;
			}
		});

		Self {
			connection,
			receiver,
			task,
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
	pub async fn open_stream<
		S: DeserializeOwned + Serialize + Send + 'static,
		R: DeserializeOwned + Serialize + Send + 'static,
	>(
		&self,
		r#type: &T,
	) -> Result<(Sender<S>, Receiver<R>), error::Stream> {
		let (sender, receiver) = self.connection.open_bi().await?;

		let sender = Sender::new(sender);
		let receiver = Receiver::new(ReceiverStream::new(receiver));

		sender.send_any(&r#type)?;

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

impl<T: DeserializeOwned + Serialize + Send + 'static> Stream for Connection<T> {
	type Item = Result<Incoming<T>, error::Connection>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		if self.receiver.is_terminated() {
			Poll::Ready(None)
		} else {
			self.receiver
				.poll_next_unpin(cx)
				.map_ok(|(sender, receiver)| Incoming::new(sender, receiver))
		}
	}
}

impl<T: DeserializeOwned + Serialize + Send + 'static> FusedStream for Connection<T> {
	fn is_terminated(&self) -> bool {
		self.receiver.is_terminated()
	}
}

struct IncomingStreams<'connection> {
	connection: &'connection quinn::Connection,
	accept: Option<Pin<Box<AcceptBi<'connection>>>>,
	shutdown: oneshot::Receiver<()>,
	sender: flume::Sender<Result<(SendStream, RecvStream), error::Connection>>,
	complete: bool,
}

impl Future for IncomingStreams<'_> {
	type Output = ();

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		if self.complete || self.connection.close_reason().is_some() {
			return Poll::Ready(());
		}

		match self.shutdown.poll_unpin(cx) {
			Poll::Ready(_) => {
				self.complete = true;
				self.accept = None;
				Poll::Ready(())
			}
			Poll::Pending => {
				loop {
					let mut accept = self
						.accept
						.take()
						.unwrap_or_else(|| Box::pin(self.connection.accept_bi()));
					match accept.poll_unpin(cx) {
						Poll::Ready(incoming) => {
							// if there is no receiver, it means that we dropped the last
							// `Endpoint`
							if self
								.sender
								.send(incoming.map_err(error::Connection))
								.is_err()
							{
								self.complete = true;
								return Poll::Ready(());
							}
						}
						Poll::Pending => {
							// Restore the same accept future to our state.
							self.accept = Some(accept);
							return Poll::Pending;
						}
					}
				}
			}
		}
	}
}
