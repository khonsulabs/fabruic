//! [`Sender`] part of a stream.

use std::{convert::TryFrom, marker::PhantomData, mem::size_of};

use bytes::{BufMut, Bytes, BytesMut};
use quinn::{SendStream, VarInt};
use serde::Serialize;

use super::Task;
use crate::error;

/// Used to send data to a stream.
#[derive(Clone, Debug)]
pub struct Sender<T: Serialize> {
	/// Send [`Serialize`]d data to the sending task.
	sender: flume::Sender<Bytes>,
	/// Holds the type to [`Serialize`] too.
	_type: PhantomData<T>,
	/// [`Task`] handle that does the sending into the stream.
	task: Task<Result<(), error::Sender>, Message>,
}

/// Messages sent to the [`Sender`] task.
#[derive(Clone, Debug)]
enum Message {
	/// Data to be sent.
	Data(Bytes),
	/// Tell [`Task`] to finish the [`Sender`] part of the stream and close it.
	Finish,
	/// Tell [`Task`] to close the [`Sender`].
	Close,
}

impl<T: Serialize> Sender<T> {
	/// Builds a new [`Sender`] from a raw [`quinn`] type. Spawns a task that
	/// sends data into the stream.
	pub(super) fn new(mut stream_sender: SendStream) -> Self {
		// sender channels
		let (sender, receiver) = flume::unbounded();

		// `Task` handling `Sender`
		let task = Task::new(|shutdown| async move {
			let mut receiver = receiver.into_stream();
			let mut shutdown = shutdown;

			while let Some(message) = allochronic_util::select! {
				message: &mut receiver => message.map(Message::Data),
				shutdown: &mut shutdown => shutdown.ok(),
			} {
				match message {
					Message::Data(bytes) => stream_sender.write_chunk(bytes).await?,
					Message::Finish => {
						stream_sender.finish().await?;
						break;
					}
					Message::Close => {
						stream_sender
							.reset(VarInt::from_u32(0))
							.map_err(|_error| error::AlreadyClosed)?;
						break;
					}
				}
			}

			Ok(())
		});

		Self {
			sender,
			_type: PhantomData,
			task,
		}
	}

	/// Send `data` into the stream.
	///
	/// # Errors
	/// - [`error::Sender::Serialize`] if `data` failed to be serialized
	/// - [`error::Sender::Write`] if the [`Sender`] failed to to write to the
	///   stream
	/// - [`error::Sender::Closed`] if the [`Sender`] is closed
	pub fn send(&self, data: &T) -> Result<(), error::Sender> {
		self.send_any(data)
	}

	/// Send any `data` into the stream. This will fail on the receiving end if
	/// not decoded into the proper type.
	///
	/// # Errors
	/// - [`error::Sender::Serialize`] if `data` failed to be serialized
	/// - [`error::Sender::Write`] if the [`Sender`] failed to to write to the
	///   stream
	/// - [`error::Sender::Closed`] if the [`Sender`] is closed
	#[allow(clippy::panic_in_result_fn, clippy::unwrap_in_result)]
	pub(super) fn send_any<A: Serialize>(&self, data: &A) -> Result<(), error::Sender> {
		let mut bytes = BytesMut::new();

		// get size
		#[allow(box_pointers)]
		let len = bincode::serialized_size(&data)?;
		// reserve an appropriate amount of space
		bytes.reserve(
			usize::try_from(len)
				.expect("not a 64-bit system")
				.checked_add(size_of::<u64>())
				.expect("data trying to be sent is too big"),
		);
		// insert length first, this enables framing
		bytes.put_u64_le(len);

		let mut bytes = bytes.writer();

		// serialize `data` into `bytes`
		#[allow(box_pointers)]
		bincode::serialize_into(&mut bytes, &data)?;

		// send data to task
		let bytes = bytes.into_inner().freeze();

		// make sure that our length is correct
		debug_assert_eq!(
			u64::try_from(bytes.len()).expect("not a 64-bit system"),
			u64::try_from(size_of::<u64>())
				.expect("not a 64-bit system")
				.checked_add(len)
				.expect("message to long")
		);

		// if the sender task has been dropped, return it's error
		if self.sender.send(bytes).is_err() {
			// TODO: configurable executor
			futures_executor::block_on(async { (&self.task).await })?
		} else {
			Ok(())
		}
	}

	/// Shut down the [`Send`] part of the stream gracefully.
	///
	/// No new data may be written after calling this method. Completes when the
	/// peer has acknowledged all sent data, retransmitting data as needed.
	///
	/// # Errors
	/// This can only return [`error::Sender::Closed`] as an [`Err`], if it was
	/// already closed, but if the [`Sender`] failed to write to the stream it
	/// will return a queued [`error::Sender::Write`].
	pub async fn finish(&self) -> Result<(), error::Sender> {
		self.task.close(Message::Finish).await?
	}

	/// Close the [`Sender`] immediately.
	///
	/// To close a [`Sender`] gracefully use [`Sender::finish`].
	///
	/// # Errors
	/// This can only return [`error::Sender::Closed`] as an [`Err`], if it was
	/// already closed, but if the [`Sender`] failed to write to the stream it
	/// will return a queued [`error::Sender::Write`].
	pub async fn close(&self) -> Result<(), error::Sender> {
		self.task.close(Message::Close).await?
	}
}
