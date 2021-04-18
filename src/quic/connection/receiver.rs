//! [`Receiver`] part of a stream.

use std::{
	fmt::{self, Debug, Formatter},
	pin::Pin,
	task::{Context, Poll},
};

use futures_channel::oneshot;
use futures_util::{stream::Stream, StreamExt};
use serde::de::DeserializeOwned;

use super::{ReceiverStream, Task};
use crate::{error, Result};

/// Used to receive data from a stream. Will stop receiving message if
/// deserialization failed.
#[derive(Clone)]
pub struct Receiver<T: 'static> {
	/// Send [`Deserialize`](serde::Deserialize)d data to the sending task.
	receiver: flume::r#async::RecvStream<'static, Result<T, error::Receiver>>,
	/// [`Task`] handle that does the receiving from the stream.
	task: Task<Result<(), error::AlreadyClosed>>,
}

impl<T> Debug for Receiver<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Receiver")
			.field("receiver", &"RecvStream")
			.field("task", &self.task)
			.finish()
	}
}

impl<T> Receiver<T> {
	/// Builds a new [`Receiver`] from a raw [`quinn`] type. Spawns a task that
	/// receives data from the stream.
	pub(super) fn new(mut stream: ReceiverStream<T>) -> Self
	where
		T: DeserializeOwned + Send,
	{
		// receiver channels
		let (sender, receiver) = flume::unbounded();
		let receiver = receiver.into_stream();

		// `Task` handling `Receiver`
		let (shutdown_sender, shutdown_receiver) = oneshot::channel();
		let task = Task::new(
			async move {
				/// Help Group Messages
				enum Message<T> {
					/// Data arrived from stream.
					Data(Result<T, error::Receiver>),
					/// [`Receiver`] asked to close.
					Close,
				}

				let mut shutdown = shutdown_receiver;

				while let Some(message) = allochronic_util::select! {
					message: &mut stream => message.map(Message::Data),
					shutdown: &mut shutdown => shutdown.ok().map(|_| Message::Close),
				} {
					match message {
						Message::Data(message) => {
							let failed = message.is_err();

							// the receiver might have been dropped
							if sender.send(message).is_err() {
								break;
							}

							if failed {
								break;
							}
						}
						Message::Close => {
							stream.stop()?;
							break;
						}
					}
				}

				Ok(())
			},
			shutdown_sender,
		);

		Self { receiver, task }
	}

	/// Wait for the [`Receiver`] part of the stream to finish gracefully.
	///
	/// This can only be achieved through the peer's
	/// [`Sender::finish`](crate::Sender::finish) or an error.
	///
	/// # Errors
	/// - [`Error::Read`](crate::Error) if the [`Receiver`] failed to read from
	///   the stream
	/// - [`error::AlreadyClosed`](crate::Error) if it has already been closed
	pub async fn finish(&self) -> Result<(), error::AlreadyClosed> {
		(&self.task).await?
	}

	/// Close the [`Receiver`] immediately. To close a [`Receiver`] gracefully
	/// use [`finish`](Self::finish).
	///
	/// # Errors
	/// - [`Error::Read`](crate::Error) if the [`Receiver`] failed to read from
	///   the stream
	/// - [`error::AlreadyClosed`](crate::Error) if it has already been closed
	pub async fn close(&self) -> Result<(), error::AlreadyClosed> {
		self.task.close(()).await?
	}
}

impl<T> Stream for Receiver<T> {
	type Item = Result<T, error::Receiver>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.receiver.poll_next_unpin(cx)
	}
}
