# signal [![Rust](https://github.com/Diesel-Jeans/signal/actions/workflows/rust.yml/badge.svg)](https://github.com/Diesel-Jeans/signal/actions/workflows/rust.yml)

## Database Setup

Make sure you have `docker-compose` installed!

1. Go into the server folder, add an .env file with the database URL in it like "DATABASE_URL=URL", and run the docker-compose

```zsh
docker-compose up
```

2. (Optionally) Open the brower on `localhost:5050` and login using the PGADMIN email and password.

3. If you havent generated certificates go into `server/cert` and run the shell script

4. Start the server, and it should successfully connect to the database. Enjoy!
