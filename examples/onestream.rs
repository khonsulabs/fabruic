use anyhow::Result;
use fabruic::{Certificate, Endpoint, PrivateKey};
use futures_util::StreamExt;

const SERVER_NAME: &str = "test";
const SERVER_PORT: u16 = 5001;
const CLIENTS: usize = 100;

#[tokio::main]
async fn main() -> Result<()> {
	// generate a certificate pair
	let (certificate, private_key) = fabruic::generate_self_signed(SERVER_NAME);

	// start the server
	tokio::spawn(run_server(certificate.clone(), private_key));
	// wait for server to start
	// tokio::time::sleep(Duration::from_millis(100)).await;

	let certificate = certificate.clone();

	// build a client
	let client = Endpoint::new_client(&certificate)?;

	let connection = client
		.connect(format!("[::1]:{}", SERVER_PORT).parse()?, SERVER_NAME)
		.await?;
	connection.close_incoming().await?;

	// initiate a stream
	let (sender, receiver) = connection.open_stream::<String, String>().await?;

	let tasks = (0..CLIENTS)
		.map(|_| {
			let sender = sender.clone();
			let mut receiver = receiver.clone();
			async move {
				sender.send(&String::from("test"))?;
				let value = receiver.next().await.expect("didn't get a response")?;
				assert_eq!(value, "test");
				Ok(())
			}
		})
		.collect::<Vec<_>>();

	futures_util::future::join_all(tasks)
		.await
		.into_iter()
		.collect::<Result<Vec<()>, fabruic::Error>>()?;

	// wait for client to finish cleanly
	client.wait_idle().await;

	Ok(())
}

async fn run_server(
	certificate: Certificate,
	private_key: PrivateKey,
) -> Result<(), fabruic::Error> {
	let mut server = Endpoint::new_server(SERVER_PORT, &certificate, &private_key)?;
	println!("[server] Listening on {}", server.local_address()?);

	// start listening to new incoming connections
	// in this example we know there is `CLIENTS` number of clients, so we will not
	// wait for more
	let mut connection = server.next().await.expect("connection failed")?;
	println!("[server] New Connection: {}", connection.remote_address());

	// start listening to new incoming streams
	// in this example we know there is only 1 incoming stream, so we will not wait
	// for more
	let incoming = connection.next().await.expect("no stream found");
	connection.close_incoming().await?;
	println!(
		"[server] New incoming stream from: {}",
		connection.remote_address()
	);

	// accept stream
	let (sender, mut receiver) = incoming.accept_stream::<String>();

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
