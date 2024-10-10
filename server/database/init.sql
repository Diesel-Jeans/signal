-- TABLES
CREATE TABLE accounts (
    id              INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    aci             VARCHAR(30) UNIQUE,
    pni             VARCHAR(30) UNIQUE,
    auth_token      VARCHAR(255) NOT NULL UNIQUE,
    identity_key    BYTEA NOT NULL
);

CREATE TABLE devices (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    device_id   TEXT NOT NULL,
    owner       INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    UNIQUE(device_id, owner)
);

CREATE TABLE msq_queue (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    a_receiver  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    d_receiver  INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    msg         BYTEA NOT NULL
);

CREATE TABLE aci_signed_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    key_id      TEXT NOT NULL UNIQUE,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL
);

CREATE TABLE pni_signed_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    key_id      TEXT NOT NULL UNIQUE,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL
);

CREATE TABLE aci_pq_last_resort_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    key_id      TEXT NOT NULL UNIQUE,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL
);

CREATE TABLE pni_pq_last_resort_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    key_id      TEXT NOT NULL UNIQUE,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL
);

CREATE TABLE device_keys (
    id                          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner                       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    aci_signed_pre_key          TEXT REFERENCES aci_signed_pre_key_store(key_id) ON DELETE CASCADE,
    pni_signed_pre_key          TEXT REFERENCES pni_signed_pre_key_store(key_id) ON DELETE CASCADE,
    aci_pq_last_resort_pre_key  TEXT REFERENCES aci_pq_last_resort_pre_key_store(key_id) ON DELETE CASCADE,
    pni_pq_last_resort_pre_key  TEXT REFERENCES pni_pq_last_resort_pre_key_store(key_id) ON DELETE CASCADE
);

CREATE TABLE one_time_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL UNIQUE,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL
);

-- DATA
-- salt = 14
-- SHA256 hash -> salt + auth_token

INSERT INTO
    accounts (aci, pni, auth_token, identity_key)
VALUES
    ('bob', NULL, '1236854bff0ad5aa206f924c9c2ff800681f69df4f6963976f144c1842c2ff1b', '\x424f424b4559'::bytea); -- auth_token = BBBBBB

INSERT INTO
    accounts (aci, pni, auth_token, identity_key)
VALUES
    ('alice', NULL, '212835c5decc07f75ab30ea7cff49fb7101ef9c7814fd40fa8084748799e5c55', '\x414c4943454b4559'::bytea); -- auth_token = AAAAAA


INSERT INTO
    devices (device_id, owner)
SELECT
    'bob_device', id
FROM
    accounts
WHERE
    aci = 'bob'
    AND pni IS NULL;

INSERT INTO
    devices (device_id, owner)
SELECT
    'alice_device', id
FROM
    accounts
WHERE
    aci = 'alice'
    AND pni IS NULL;