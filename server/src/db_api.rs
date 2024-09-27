use tokio_postgres::{ NoTls, Error };


pub async fn add_user() -> Result<(), Error> {
	let (client, connection) = tokio_postgres::connect("host=localhost user=postgres", NoTls).await?;

	tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

	let name = "foo";
	let age = 5;
    let affected_rows = client
    	.execute("INSERT INTO person (name, age) VALUES ($1, $2)", &[&name, &age.to_owned()])
        .await?;

    assert_eq!(affected_rows, 1);

	Ok(())
}

pub fn get_user() {
	
}

pub fn update_user() {

}

pub fn delete_user() {

}

pub fn add_device() {

}

pub fn get_device() {

}

pub fn delete_device() {

}

pub fn push_msg_queue() {

}

pub fn pop_msg_queue() {

}

pub fn store_key_bundle() {

}

pub fn get_key_bundle() {

}