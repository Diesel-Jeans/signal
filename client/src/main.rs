use hello_world::greeter_client::GreeterClient;
use hello_world::HelloRequest;
use std::io;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = GreeterClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(HelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}

#[allow(dead_code)]
fn login() {
    let mut username = String::new();

    println!("Welcome, please enter your username");

    match io::stdin().read_line(&mut username) {
        Err(error) => {
            println!("Username fmt error, {}", error);
            todo!()
        }
        Ok(_) => {}
    }

    let mut password = String::new();
    let set_password = false;
    let tries = 3; // Can be a changed later if this needs to be tied to the server in anyway
                   // for security

    while (tries > 0) && !set_password {
        match io::stdin().read_line(&mut password) {
            Err(error) => {
                println!("{}", error);
                continue;
            }
            Ok(_) => {
                todo!() // Check on the server if the password is correct, if yes, change the
                        // set_password to true, else, continue and let
                        // the user try again
            }
        }
    }
}
