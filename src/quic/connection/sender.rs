//! [`Sender`] part of a stream.

use std::{convert::TryFrom, marker::PhantomData, mem::size_of};

use bytes::{BufMut, Bytes, BytesMut};
use futures_channel::oneshot;
use quinn::{SendStream, VarInt};
use serde::Serialize;

use super::Task;
use crate::{Error, Result};

/// Used to send data to a stream.
#[derive(Clone, Debug)]
pub struct Sender<T: Serialize> {
	/// Send [`Serialize`]d data to the sending task.
	sender: flume::Sender<Bytes>,
	/// Holds the type to [`Serialize`] too.
	_type: PhantomData<T>,
	/// [`Task`] handle that does the sending into the stream.
	task: Task<Result<()>, Message>,
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
		let (shutdown_sender, shutdown_receiver) = oneshot::channel();
		let task = Task::new(
			async move {
				let mut receiver = receiver.into_stream();
				let mut shutdown = shutdown_receiver;

				while let Some(message) = allochronic_util::select! {
					message: &mut receiver => message.map(Message::Data),
					shutdown: &mut shutdown => shutdown.ok(),
				} {
					match message {
						Message::Data(bytes) => stream_sender
							.write_chunk(bytes)
							.await
							.map_err(Error::Write)?,
						Message::Finish => {
							stream_sender.finish().await.map_err(Error::Finish)?;
							break;
						}
						Message::Close => {
							stream_sender
								.reset(VarInt::from_u32(0))
								.map_err(|_error| Error::AlreadyClosed)?;
							break;
						}
					}
				}

				Ok(())
			},
			shutdown_sender,
		);

		Self {
			sender,
			_type: PhantomData,
			task,
		}
	}

	/// Send `data` into the stream.
	///
	/// # Errors
	/// - [`Error::Serialize`] if `data` failed to be serialized
	/// - [`Error::Send`] if `data` failed to be sent
	// TODO: update Clippy
	#[allow(clippy::panic_in_result_fn, clippy::unwrap_in_result)]
	pub fn send(&self, data: &T) -> Result<()> {
		let mut bytes = BytesMut::new();

		// get size
		#[allow(box_pointers)]
		let len = bincode::serialized_size(&data).map_err(|error| Error::Serialize(*error))?;
		// reserve an appropriate amount of space
		#[allow(clippy::expect_used)]
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
		bincode::serialize_into(&mut bytes, &data).map_err(|error| Error::Serialize(*error))?;

		// send data to task
		let bytes = bytes.into_inner().freeze();

		// make sure that our length is correct
		#[allow(clippy::expect_used)]
		{
			debug_assert_eq!(
				u64::try_from(bytes.len()).expect("not a 64-bit system"),
				u64::try_from(size_of::<u64>())
					.expect("not a 64-bit system")
					.checked_add(len)
					.expect("message to long")
			);
		}

		self.sender.send(bytes).map_err(|_bytes| Error::Send)
	}

	/// Send any `data` into the stream. This will fail on the receiving end if
	/// not decoded into the proper type.
	///
	/// # Errors
	/// - [`Error::Serialize`] if `data` failed to be serialized
	/// - [`Error::Send`] if `data` failed to be sent
	// TODO: update Clippy
	#[allow(clippy::panic_in_result_fn, clippy::unwrap_in_result)]
	pub(super) fn send_any<A: Serialize>(&self, data: &A) -> Result<()> {
		let mut bytes = BytesMut::new();

		// get size
		#[allow(box_pointers)]
		let len = bincode::serialized_size(&data).map_err(|error| Error::Serialize(*error))?;
		// reserve an appropriate amount of space
		#[allow(clippy::expect_used)]
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
		bincode::serialize_into(&mut bytes, &data).map_err(|error| Error::Serialize(*error))?;

		// send data to task
		let bytes = bytes.into_inner().freeze();

		// make sure that our length is correct
		#[allow(clippy::expect_used)]
		{
			debug_assert_eq!(
				u64::try_from(bytes.len()).expect("not a 64-bit system"),
				u64::try_from(size_of::<u64>())
					.expect("not a 64-bit system")
					.checked_add(len)
					.expect("message to long")
			);
		}

		self.sender.send(bytes).map_err(|_bytes| Error::Send)
	}

	/// Shut down the [`Send`] part of the stream gracefully.
	///
	/// No new data may be written after calling this method. Completes when the
	/// peer has acknowledged all sent data, retransmitting data as needed.
	///
	/// # Errors
	/// - [`Error::AlreadyClosed`] if it was already finished
	/// - [`Error::Write`] if the [`Sender`] failed to write to the stream
	/// - [`Error::Finish`] if the [`finish`](Self::finish) failed to finish the
	///   stream
	pub async fn finish(&self) -> Result<()> {
		self.task.close(Message::Finish).await?
	}

	/// Close the [`Sender`] immediately.
	///
	/// To close a [`Sender`] gracefully use [`Sender::finish`].
	///
	/// # Errors
	/// This can only return [`Error::AlreadyClosed`] as an [`Err`], if it was
	/// already closed, but there could be other errors queued up in the
	/// [`Sender`]:
	/// - [`Error::Write`] if the [`Sender`] failed to write to the stream
	/// - [`Error::Finish`] if the [`finish`](Self::finish) failed to finish the
	///   stream
	pub async fn close(&self) -> Result<()> {
		self.task.close(Message::Close).await?
	}
}
