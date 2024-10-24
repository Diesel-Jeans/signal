CREATE TABLE accounts (
    id                INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    aci               VARCHAR(16) NOT NULL UNIQUE,
    pni               VARCHAR(20) NOT NULL UNIQUE,
    aci_identity_key  BYTEA NOT NULL,
    pni_identity_key  BYTEA NOT NULL,
    phone_number      TEXT NOT NULL UNIQUE,
    account_attr      BYTEA NOT NULL
);

CREATE TABLE devices (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner       INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id   TEXT NOT NULL,
    name        BYTEA NOT NULL,
    auth_token  VARCHAR(255) NOT NULL UNIQUE,
    salt        TEXT NOT NULL,
    UNIQUE(device_id, owner)
);

CREATE TABLE msq_queue (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    receiver    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
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

CREATE TABLE one_time_ec_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL,
    public_key  bytea NOT NULL,
    UNIQUE(owner, key_id)
);

CREATE TABLE one_time_pq_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL,
    public_key  bytea NOT NULL,
    signature   bytea,
    UNIQUE(owner, key_id)
);

INSERT INTO
    accounts (aci, pni, aci_identity_key, pni_identity_key, phone_number, account_attr)
VALUES
    ('bob', 'PNI:1234', '\x053b258970748dff667800108898e390a1dfabd8fa66889748d903c12fbc5c732d'::BYTEA, 'x1234'::BYTEA, '12345678', 'x4865'::BYTEA); -- auth_token = BBBBBB

INSERT INTO
    accounts (aci, pni, aci_identity_key, pni_identity_key, phone_number, account_attr)
VALUES
    ('alice', 'PNI:5678', '\x414c4943454b4559'::BYTEA, '\x5678'::BYTEA, '87654321', 'x4558'::BYTEA); -- auth_token = AAAAAA

