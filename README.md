# signal [![Rust](https://github.com/Diesel-Jeans/signal/actions/workflows/rust.yml/badge.svg)](https://github.com/Diesel-Jeans/signal/actions/workflows/rust.yml)

## Database Setup

Make sure you have `docker-compose` installed!

1. Go into the server folder and start the docker-compose

```zsh
docker-compose up
```

2. Open the brower on `localhost:5050` and login using the PGADMIN email and password.

3. Create a new database:
   - Name it signal_db.
   - In the "Connection" tab, set the username and password the same as in the `docker-compose.yml` file.
   - Also in the "Connection" tab, set the ipaddress to the ipaddress of the container. You can find it using `docker inspect CONTAINER_ID`. (CONTAINER_ID can be found in `docker container ls`)

4. Start the server, and it should successfully connect to the database. Enjoy!
