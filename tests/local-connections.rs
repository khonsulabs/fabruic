use anyhow::{Error, Result};
use fabruic::{Endpoint, KeyPair};
use futures_util::{future, StreamExt, TryFutureExt};
use transmog::{Format, OwnedDeserializer};
use transmog_bincode::Bincode;
use transmog_pot::Pot;

const SERVER_NAME: &str = "test";
const CLIENTS: usize = 100;

async fn simulate_client_and_server<F>(format: F) -> Result<()>
where
	F: OwnedDeserializer<()> + OwnedDeserializer<String> + Clone + 'static,
	<F as Format<'static, ()>>::Error: Send + Sync + 'static,
	<F as Format<'static, String>>::Error: Send + Sync + 'static,
{
	// collect all tasks
	let mut clients = Vec::with_capacity(CLIENTS);

	// generate a certificate pair
	let key_pair = KeyPair::new_self_signed(SERVER_NAME);

	// build the server
	// we want to do this outside to reserve the `SERVER_PORT`, otherwise spawned
	// clients may take it
	let mut server = Endpoint::new_server(0, key_pair.clone())?;
	let address = format!("quic://{}", server.local_address()?);

	// start 100 clients
	for index in 0..CLIENTS {
		let address = address.clone();
		let certificate = key_pair.end_entity_certificate().clone();

		let task_format = format.clone();
		clients.push(
			tokio::spawn(async move {
				// build a client
				let client = Endpoint::new_client()?;

				let connecting = client.connect_pinned(address, &certificate, None).await?;
				println!(
					"[client:{}] Connecting to {}",
					index,
					connecting.remote_address()
				);
				let connection = connecting.accept::<(), _>(task_format).await?;
				println!(
					"[client:{}] Successfully connected to {}",
					index,
					connection.remote_address()
				);
				connection.close_incoming().await?;

				// initiate a stream
				let (sender, mut receiver) = connection.open_stream::<String, String>(&()).await?;
				println!(
					"[client:{}] Successfully opened stream to {}",
					index,
					connection.remote_address()
				);

				// send message
				sender.send(&format!("hello from client {}", index))?;

				// start listening to new incoming messages
				// in this example we know there is only 1 incoming message, so we will
				// not wait for more
				let message = receiver.next().await.expect("no message found")?;
				println!(
					"[client:{}] New message from {}: {}",
					index,
					connection.remote_address(),
					message
				);

				// wait for stream to finish
				sender.finish().await?;
				receiver.finish().await?;

				// wait for client to finish cleanly
				client.wait_idle().await;
				println!(
					"[client:{}] Successfully finished {}",
					index,
					client.local_address()?
				);

				Result::<_, Error>::Ok(())
			})
			.map_err(Error::from)
			.and_then(future::ready),
		);
	}

	// start the server
	println!("[server] Listening on {}", server.local_address()?);

	// collect incoming connection tasks
	let mut connections = Vec::with_capacity(CLIENTS);

	// start listening to new incoming connections
	// in this example we know there is `CLIENTS` number of clients, so we will not
	// wait for more
	for _ in 0..CLIENTS {
		let connecting = server.next().await.expect("connection failed");

		println!(
			"[server] New incoming Connection: {}",
			connecting.remote_address()
		);

		let task_format = format.clone();
		// every new incoming connections is handled in it's own task
		connections.push(
			tokio::spawn(async move {
				let mut connection = connecting.accept::<(), _>(task_format.clone()).await?;
				println!("[server] New Connection: {}", connection.remote_address());

				// start listening to new incoming streams
				// in this example we know there is only 1 incoming stream, so we will not wait
				// for more
				let incoming = connection.next().await.expect("no stream found")?;
				connection.close_incoming().await?;
				println!(
					"[server] New incoming stream from: {}",
					connection.remote_address()
				);

				// accept stream
				let (sender, mut receiver) = incoming.accept::<String, String>().await?;

				// start listening to new incoming messages
				// in this example we know there is only 1 incoming message, so we will not wait
				// for more
				let message = receiver.next().await.expect("no message found")?;
				println!(
					"[server] New message from {}: {}",
					connection.remote_address(),
					message
				);

				// respond
				sender.send(&String::from("hello from server"))?;

				// wait for stream to finish
				sender.finish().await?;
				receiver.finish().await?;

				Result::<_, Error>::Ok(())
			})
			.map_err(Error::from)
			.and_then(future::ready),
		);
	}

	server.close_incoming().await?;

	// wait for all connections to finish
	future::try_join_all(connections).await?;

	// wait for server to finish cleanly
	server.wait_idle().await;
	println!("[server] Successfully finished {}", server.local_address()?);

	future::try_join_all(clients).await?;

	Ok(())
}

#[tokio::test]
async fn format_without_serialized_size() -> Result<()> {
	simulate_client_and_server(Pot::default()).await
}

#[tokio::main]
#[cfg_attr(test, test)]
async fn format_with_serialized_size() -> Result<()> {
	simulate_client_and_server(Bincode::default()).await
}
