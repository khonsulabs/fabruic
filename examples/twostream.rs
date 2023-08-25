//! TODO

#![allow(clippy::missing_docs_in_private_items)]

use anyhow::{Error, Result};
use fabruic::{Endpoint, Incoming, KeyPair};
use futures_util::StreamExt;

const SERVER_NAME: &str = "test";
const SERVER_PORT: u16 = 5002;
const REQUESTS_PER_STREAM: usize = 10;
const STREAMS: usize = 1000;

#[tokio::main(worker_threads = 16)]
#[cfg_attr(test, test)]
async fn main() -> Result<()> {
	// generate a certificate pair
	let key_pair = KeyPair::new_self_signed(SERVER_NAME);

	// start the server
	let server = Endpoint::new_server(SERVER_PORT, key_pair.clone())?;
	let address = format!("quic://{}", server.local_address()?);
	println!("[server] Listening on {address}");
	tokio::spawn(run_server(server));

	// build a client
	let client = Endpoint::new_client()?;

	let connection = client
		.connect_pinned(address, key_pair.end_entity_certificate(), None)
		.await?
		.accept::<()>()
		.await?;
	connection.close_incoming().await?;

	// initiate a stream

	let tasks = (0..STREAMS)
		.map(|_| async {
			let (sender, receiver) = connection.open_stream::<String, String>(&()).await.unwrap();
			(0..REQUESTS_PER_STREAM).for_each(|_| {
				let sender = sender.clone();
				let mut receiver = receiver.clone();
				tokio::task::spawn(async move {
					sender.send(&String::from("test"))?;
					let value = receiver.next().await.expect("didn't get a response")?;
					assert_eq!(value, "test");
					Result::<(), Error>::Ok(())
				});
			});
			Ok(())
		})
		.collect::<Vec<_>>();

	futures_util::future::join_all(tasks)
		.await
		.into_iter()
		.collect::<Result<Vec<()>, Error>>()
		.unwrap();

	// wait for client to finish cleanly
	client.wait_idle().await;

	Ok(())
}

async fn run_server(mut server: Endpoint) -> Result<(), Error> {
	// start listening to new incoming connections
	// in this example we know there is `CLIENTS` number of clients, so we will not
	// wait for more
	while let Some(connection) = server.next().await {
		let connection = connection.accept::<()>().await?;
		println!("[server] New Connection: {}", connection.remote_address());

		// every new incoming connections is handled in it's own task
		tokio::spawn(run_connection(connection));
	}

	Ok(())
}

async fn run_connection(mut connection: fabruic::Connection<()>) -> Result<(), Error> {
	// start listening to new incoming streams
	// in this example we know there is only 1 incoming stream, so we will not wait
	// for more
	while let Some(incoming) = connection.next().await {
		// connection.close_incoming().await?;
		/*println!(
			"[server] New incoming stream from: {}",
			connection.remote_address()
		);*/

		tokio::spawn(run_stream(incoming?));
	}

	Ok(())
}

async fn run_stream(incoming: Incoming<()>) -> Result<(), Error> {
	let (sender, mut receiver) = incoming.accept::<String, String>().await?;

	// start listening to new incoming messages
	// in this example we know there is only 1 incoming message, so we will not wait
	// for more
	while let Some(message) = receiver.next().await {
		let message = message?;
		sender.send(&message)?;
	}

	// wait for stream to finish
	sender.finish().await?;
	receiver.finish().await?;

	Ok(())
}
