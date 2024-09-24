-- Add migration script here
CREATE TABLE users (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    username    VARCHAR(30) NOT NULL UNIQUE,
    password    VARCHAR(30) NOT NULL
);

CREATE TABLE devices (
    id      INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE msq_queue (
    id      INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    reciver INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    msg     bytea NOT NULL
);

CREATE TABLE aci_signed_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    key_id      INTEGER NOT NULL,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL
);

CREATE TABLE pni_signed_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    key_id      INTEGER NOT NULL,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL
);

CREATE TABLE aci_pq_last_resort_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    key_id      INTEGER NOT NULL,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL
);

CREATE TABLE pni_pq_last_resort_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    key_id      INTEGER NOT NULL,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL
);

CREATE TABLE device_keys (
    id                          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner                       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    aci_signed_pre_key          INTEGER REFERENCES aci_signed_pre_key_store(id) ON DELETE CASCADE,
    pni_signed_pre_key          INTEGER REFERENCES pni_signed_pre_key_store(id) ON DELETE CASCADE,
    aci_pq_last_resort_pre_key  INTEGER REFERENCES aci_pq_last_resort_pre_key_store(id) ON DELETE CASCADE,
    pni_pq_last_resort_pre_key  INTEGER REFERENCES pni_pq_last_resort_pre_key_store(id) ON DELETE CASCADE,
    identity_key                bytea NOT NULL
);

CREATE TABLE one_time_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    key_id      INTEGER NOT NULL,
    owner       INTEGER NOT NULL REFERENCES device_keys(id) ON DELETE CASCADE,
    public_key  bytea NOT NULL
);
