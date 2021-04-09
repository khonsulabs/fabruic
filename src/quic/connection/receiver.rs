//! [`Receiver`] part of a stream.

use std::{
	convert::TryFrom,
	fmt::{self, Debug, Formatter},
	mem::size_of,
	pin::Pin,
	task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_channel::oneshot;
use futures_util::{stream::Stream, StreamExt};
use quinn::{Chunk, VarInt};
use serde::de::DeserializeOwned;

use super::Task;
use crate::{Error, Result};

/// Used to receive data from a stream.
///
///  # Errors
/// [`Error::Deserialize`] if `data` failed to be
/// [`Deserialize`](serde::Deserialize)d.
#[derive(Clone)]
pub struct Receiver<T: 'static> {
	/// Send [`Deserialize`](serde::Deserialize)d data to the sending task.
	receiver: flume::r#async::RecvStream<'static, Result<T>>,
	/// [`Task`] handle that does the receiving from the stream.
	task: Task<Result<()>>,
}

impl<T> Debug for Receiver<T> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_struct("Receiver")
			.field("receiver", &"RecvStream<Result<T>>")
			.field("task", &self.task)
			.finish()
	}
}

impl<T> Receiver<T> {
	/// Builds a new [`Receiver`] from a raw [`quinn`] type. Spawns a task that
	/// receives data from the stream.
	pub(super) fn new(mut stream: quinn::RecvStream) -> Self
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
				enum Message {
					/// Data arrived from stream.
					Data(Bytes),
					/// [`Receiver`] asked to close.
					Close,
				}

				let mut reader = stream.read_chunk(size_of::<u64>(), true);
				let mut shutdown = shutdown_receiver;

				let mut length = 0;
				// 1480 bytes is a default MTU size configured by quinn-proto
				let mut data = BytesMut::with_capacity(1480);

				while let Some(message) = allochronic_util::select! {
					message: &mut reader => {
						message
							.map_err(Error::Read)?
							.map(|Chunk { bytes, .. }| Message::Data(bytes))
					},
					shutdown: &mut shutdown => shutdown.ok().map(|_| Message::Close),
				} {
					match message {
						Message::Data(bytes) => {
							let (data, length) = Self::read_internal(&mut data, &mut length, bytes);

							if let Some(data) = data {
								// the receiver might have been dropped
								if sender.send(data).is_err() {
									break;
								}
							}

							// `read_internal` calculated how much we need to read next
							reader = stream.read_chunk(length, true);
						}
						Message::Close => {
							stream
								.stop(VarInt::from_u32(0))
								.map_err(|_error| Error::AlreadyClosed)?;
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

	/// Reads messages from the stream. Calculates the amount needed to read for
	/// the next message. Returns [`Some`] if a message has completed.
	///
	///  # Errors
	/// [`Error::Deserialize`] if a message failed to be
	/// [`Deserialize`](serde::Deserialize)d.
	#[allow(clippy::unwrap_in_result)]
	fn read_internal<A: DeserializeOwned>(
		data: &mut BytesMut,
		length: &mut usize,
		bytes: Bytes,
	) -> (Option<Result<A>>, usize) {
		// reserves enough space to put in incoming bytes
		data.reserve(bytes.len());
		data.put(bytes);

		// if we don't have a length already
		if *length == 0 {
			// and there is enough to aquire it
			#[allow(clippy::expect_used)]
			if data.len() >= size_of::<u64>() {
				// aquire the length by reading the first 8 bytes (u64)
				*length = usize::try_from(data.get_uint_le(size_of::<u64>()))
					.expect("not a 64-bit system");
				// demand the amount we need
				(None, *length)
			}
			// or we don't have enough data to complete 8 bytes (u64)
			else {
				// reduce the next amount to be read to what we need to reach 8
				// bytes (u64)
				(
					None,
					size_of::<u64>()
						.checked_sub(data.len())
						.expect("wrong u64 length"),
				)
			}
		}
		// if we have a length
		else {
			// and the data we gathered is enough
			if data.len() >= *length {
				// split of the correct amoutn of data from what we have
				// gathered until now
				let data = data.split_to(*length).reader();
				// reset the length so the condition above works again
				*length = 0;

				// deserialize data
				// TODO: configure bincode, for example make it bounded
				#[allow(box_pointers)]
				let data = bincode::deserialize_from(data).map_err(|error| Error::Deserialize(*error));

				// we are done reading, let's get the next length
				(Some(data), size_of::<u64>())
			}
			// or the data is not long enough
			else {
				// reduce the next amount to be read to what we need to the data
				// length
				#[allow(clippy::expect_used)]
				(
					None,
					length.checked_sub(data.len()).expect("wrong data length"),
				)
			}
		}
	}

	/// Wait for the [`Receiver`] part of the stream to finish gracefully.
	///
	/// This can only be achieved through the peer's
	/// [`Sender::finish`](crate::Sender::finish) or an error.
	///
	/// # Errors
	/// - [`Error::Read`] if the [`Receiver`] failed to read from the stream
	/// - [`Error::AlreadyClosed`] if it has already been closed
	pub async fn finish(&self) -> Result<()> {
		(&self.task).await?
	}

	/// Close the [`Receiver`] immediately. To close a [`Receiver`] gracefully
	/// use [`finish`](Self::finish).
	///
	/// # Errors
	/// - [`Error::Read`] if the [`Receiver`] failed to read from the stream
	/// - [`Error::AlreadyClosed`] if it has already been closed
	pub async fn close(&self) -> Result<()> {
		self.task.close(()).await?
	}
}

impl<T> Stream for Receiver<T> {
	type Item = Result<T>;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		self.receiver.poll_next_unpin(cx)
	}
}
