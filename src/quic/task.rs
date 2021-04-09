//! Wrapper to handle closing async tasks in a concurrent way.

use std::{
	future::Future,
	panic,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
};

use futures_channel::oneshot::Sender;
use futures_util::FutureExt;
use parking_lot::Mutex;
use tokio::task::{JoinError, JoinHandle};

use crate::{Error, Result};

/// Wrapper to abort tasks when they are dropped.
#[derive(Debug)]
pub(super) struct Task<R, S = ()>(Arc<Mutex<Option<Inner<R, S>>>>);

impl<R, S> Clone for Task<R, S> {
	fn clone(&self) -> Self {
		Self(Arc::clone(&self.0))
	}
}

/// Inner wrapper for [`Task`].
#[derive(Debug)]
struct Inner<R, S> {
	/// Async task handle.
	handle: JoinHandle<R>,
	/// Channel for close signal.
	close: Sender<S>,
}

impl<R> Task<R> {
	/// Builds a new [`Task`].
	#[allow(clippy::new_ret_no_self)]
	pub(super) fn new<T, S>(task: T, close: Sender<S>) -> Task<R, S>
	where
		T: Future<Output = R> + Send + 'static,
		T::Output: Send + 'static,
	{
		// TODO: configurable executor
		let handle = tokio::spawn(task);

		Task(Arc::new(Mutex::new(Some(Inner { handle, close }))))
	}

	/// Builds a new empty [`Task`] that is already closed. This is useful to
	/// not have to wrap [`Task`] in another [`Option`].
	pub(super) fn empty() -> Self {
		Self(Arc::new(Mutex::new(None)))
	}
}

impl<R, S> Task<R, S> {
	/// Shuts down the [`Task`] by sending the close signal. Futher calls to
	/// [`close`](Self::close) or [`poll`](Future::poll)ing the [`Task`] will
	/// result in [`Error::AlreadyClosed`].
	///
	/// # Notes
	/// The user is responsible to handle close messages through the
	/// [`Receiver`](futures_channel::oneshot::Receiver).
	///
	/// # Panics
	/// Will propagate any panics that happened in the task.
	pub(super) async fn close(&self, message: S) -> Result<R> {
		if let Some(Inner { handle, close }) = self.0.lock().take() {
			// task could have finished and dropped the receiver, it's also possible that
			// the receiver got dropped otherwise, in any case, not our problem
			let _result = close.send(message);

			#[allow(box_pointers)]
			match handle.await.map_err(JoinError::into_panic) {
				Ok(result) => Ok(result),
				// propagate any panics
				Err(panic) => panic::resume_unwind(panic),
			}
		} else {
			Err(Error::AlreadyClosed)
		}
	}
}

impl<R, S> Future for &Task<R, S> {
	type Output = Result<R>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		// save the lock in a separate variable to be able to drop it
		let mut inner = self.0.lock();

		if let Some(Inner { handle, .. }) = inner.as_mut() {
			if let Poll::Ready(result) = handle.poll_unpin(cx) {
				// drop inner, `close` might be called simultaneously, so we don't handle this
				let _inner = inner.take();
				// drop `Mutex` before doing anything rash (parking_lot `Mutex` can't be
				// poisoned anyway)
				drop(inner);

				#[allow(box_pointers)]
				match result.map_err(JoinError::into_panic) {
					Ok(result) => Poll::Ready(Ok(result)),
					// propagate any panics
					Err(panic) => panic::resume_unwind(panic),
				}
			} else {
				Poll::Pending
			}
		} else {
			Poll::Ready(Err(Error::AlreadyClosed))
		}
	}
}

#[cfg(test)]
mod test {
	use allochronic_util::select;
	use anyhow::{Error, Result};
	use futures_channel::oneshot;
	use futures_util::StreamExt;

	use super::Task;

	#[tokio::test]
	async fn task() -> Result<()> {
		let (sender, receiver) = flume::unbounded();
		let (tester_sender, tester_receiver) = flume::unbounded();
		let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();

		let task = Task::new(
			async move {
				let mut receiver = receiver.into_stream();

				while let Some(message) = select!(
					message: &mut receiver => message,
					_: &mut shutdown_receiver => None,
				) {
					// send back our messages
					tester_sender.send(message)?;
				}

				// return `true`
				Result::<_, Error>::Ok(true)
			},
			shutdown_sender,
		);

		// send a 100 messages
		for item in 0_usize..100 {
			sender.send(item)?;
		}

		// validate our returned value
		assert_eq!(true, task.close(()).await??);
		// validate that `close` has properly closed
		assert!(matches!((&task).await, Err(crate::Error::AlreadyClosed)));

		// validate that we correctly sent all messages before shutting down
		let mut tester_receiver = tester_receiver.into_stream();
		let mut validate = 0;

		while let Some(item) = tester_receiver.next().await {
			assert_eq!(validate, item);
			validate += 1;
		}

		Ok(())
	}

	#[tokio::test]
	#[should_panic = "test"]
	async fn panic_poll() {
		let (shutdown_sender, _) = oneshot::channel::<()>();

		let task = Task::new(
			async move {
				panic!("test");
			},
			shutdown_sender,
		);

		(&task).await.expect("should panic before unwrapping");
	}

	#[tokio::test]
	#[should_panic = "test"]
	async fn panic_close() {
		let (shutdown_sender, _) = oneshot::channel();

		let task = Task::new(
			async move {
				panic!("test");
			},
			shutdown_sender,
		);

		task.close(())
			.await
			.expect("should panic before unwrapping");
	}
}
