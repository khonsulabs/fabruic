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
use futures_channel::oneshot;
use futures_util::{
	stream::{self, FusedStream},
	StreamExt,
};
pub use incoming::Incoming;
use pin_project::pin_project;
use quinn::{IncomingBiStreams, VarInt};
pub use receiver::Receiver;
use receiver_stream::ReceiverStream;
pub use sender::Sender;
use serde::{de::DeserializeOwned, Serialize};
use stream::Stream;

use super::Task;
use crate::{Error, Result};

/// Represents an open connection. Receives [`Incoming`] through [`Stream`].
#[pin_project]
#[derive(Clone)]
pub struct Connection<T: DeserializeOwned + Serialize + Send + 'static> {
	/// Initiate new connections or close socket.
	connection: quinn::Connection,
	/// Receive incoming streams.
	receiver: RecvStream<'static, Incoming<T>>,
	/// [`Task`] handling new incoming streams.
	task: Task<Result<()>>,
	/// Type for type negotiation for new streams.
	types: PhantomData<T>,
}

impl<T: DeserializeOwned + Serialize + Send + 'static> Debug for Connection<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Connection")
			.field("connection", &self.connection)
			.field("receiver", &"RecvStream<Result<Incoming>>")
			.field("task", &self.task)
			.finish()
	}
}

impl<T: DeserializeOwned + Serialize + Send + 'static> Connection<T> {
	/// Builds a new [`Connection`] from raw [`quinn`] types.
	pub(super) fn new(connection: quinn::Connection, mut bi_streams: IncomingBiStreams) -> Self {
		// channels for passing down new `Incoming` `Connection`s
		let (sender, receiver) = flume::unbounded();
		let receiver = receiver.into_stream();

		// `Task` handling incoming streams
		let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();
		let task = Task::new(
			async move {
				while let Some(connecting) = allochronic_util::select! {
					connecting: &mut bi_streams => connecting,
					_: &mut shutdown_receiver => None,
				} {
					match connecting {
						Ok((incoming_sender, incoming_receiver)) =>
							if sender
								.send(Incoming::new(incoming_sender, incoming_receiver))
								.is_err()
							{
								// if there is no receiver, it means that we dropped the last
								// `Connection`
								break;
							},

						Err(error) => return Err(Error::ReceiveStream(error)),
					}
				}

				Ok(())
			},
			shutdown_sender,
		);

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
	/// - [`Error::OpenStream`] if opening a stream failed
	/// - [`Error::Serialize`] if `type` failed to be serialized
	/// - [`Error::Send`] if `type` failed to be sent
	pub async fn open_stream<
		S: DeserializeOwned + Serialize + Send + 'static,
		R: DeserializeOwned + Serialize + Send + 'static,
	>(
		&self,
		r#type: &T,
	) -> Result<(Sender<S>, Receiver<R>)> {
		let (sender, receiver) = self.connection.open_bi().await.map_err(Error::OpenStream)?;

		let sender = Sender::new(sender);
		let receiver = Receiver::new(ReceiverStream::new(receiver));

		sender.send_any(&r#type)?;

		Ok((sender, receiver))
	}

	/// The negotiated application protocol. See
	/// [`Builder::set_protocols`](crate::Builder::set_protocols).
	#[must_use]
	pub fn protocol(&self) -> Option<Vec<u8>> {
		self.connection
			.handshake_data()
			.and_then(|data| data.protocol)
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
	/// - [`Error::ReceiveStream`] if the connection was lost
	/// - [`Error::AlreadyClosed`] if it was already closed
	pub async fn close_incoming(&self) -> Result<()> {
		self.task.close(()).await?
	}

	/// Close the [`Connection`] immediately.
	///
	/// To close a [`Connection`] gracefully use [`Sender::finish`], the
	/// [`Receiver`] can't be gracefully closed from the receiving end.
	///
	/// # Errors
	/// - [`Error::ReceiveStream`] if the connection was lost
	/// - [`Error::AlreadyClosed`] if it was already closed
	pub async fn close(&self) -> Result<()> {
		self.connection.close(VarInt::from_u32(0), &[]);
		(&self.task).await?
	}
}

impl<T: DeserializeOwned + Serialize + Send + 'static> Stream for Connection<T> {
	type Item = Incoming<T>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		if self.receiver.is_terminated() {
			Poll::Ready(None)
		} else {
			self.receiver.poll_next_unpin(cx)
		}
	}
}

impl<T: DeserializeOwned + Serialize + Send + 'static> FusedStream for Connection<T> {
	fn is_terminated(&self) -> bool {
		self.receiver.is_terminated()
	}
}
