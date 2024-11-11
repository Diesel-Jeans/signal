CREATE TABLE accounts (
    id                INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    aci               VARCHAR(36) NOT NULL UNIQUE,
    pni               VARCHAR(40) NOT NULL UNIQUE,
    aci_identity_key  BYTEA NOT NULL,
    pni_identity_key  BYTEA NOT NULL,
    phone_number      TEXT NOT NULL UNIQUE,
    account_attr      BYTEA NOT NULL
);

CREATE TABLE devices (
    id              INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner           INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id       TEXT NOT NULL,
    name            BYTEA NOT NULL,
    auth_token      BYTEA NOT NULL,
    salt            TEXT NOT NULL,
    registration_id TEXT NOT NULL,
    pni_registration_id TEXT NOT NULL,
    UNIQUE(device_id, owner)
);

CREATE TABLE msq_queue (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    receiver    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    msg         BYTEA NOT NULL
);

CREATE TABLE aci_signed_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL,
    UNIQUE(owner, key_id)

);

CREATE TABLE pni_signed_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL,
    UNIQUE(owner, key_id)

);

CREATE TABLE aci_pq_last_resort_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL,
    UNIQUE(owner, key_id)

);

CREATE TABLE pni_pq_last_resort_pre_key_store (
    id          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id      TEXT NOT NULL,
    public_key  bytea NOT NULL,
    signature   bytea NOT NULL,
    UNIQUE(owner, key_id)
);

CREATE TABLE device_keys (
    id                          INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner                       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    aci_signed_pre_key          INTEGER REFERENCES aci_signed_pre_key_store(id) ON DELETE CASCADE,
    pni_signed_pre_key          INTEGER REFERENCES pni_signed_pre_key_store(id) ON DELETE CASCADE,
    aci_pq_last_resort_pre_key  INTEGER REFERENCES aci_pq_last_resort_pre_key_store(id) ON DELETE CASCADE,
    pni_pq_last_resort_pre_key  INTEGER REFERENCES pni_pq_last_resort_pre_key_store(id) ON DELETE CASCADE
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
    ('0d76041e-54ce-4cea-a128-ebfa32171c29', 'PNI:93c5486c-5bba-437f-a9c1-0570cb619d27', '\x0531840a62513f5a0388b658978aba393e1501cc3438588019fbd8d6136f17f815'::BYTEA, '\x05c288f7a6bf5321cf151b596c7ea9cb1d279576affce0d671992baba7f19b76e7'::BYTEA, '12345678', '\x00010000000100000000000000000000000000000000'::BYTEA); -- keys have to start with 05 and be over 64 bytes

INSERT INTO 
    devices (owner, device_id, name, auth_token, salt, registration_id, pni_registration_id)
VALUES
    (1, '1', '\x1234'::BYTEA , '\x2998fa253a711f6585de13634b50e4b5c67646307cb903b8c3e6febba813937d'::BYTEA, 'salt', '1', '1'); -- password = password 

INSERT INTO 
    devices (owner, device_id, name, auth_token, salt, registration_id, pni_registration_id)
VALUES
    (1, '2', '\x5678'::BYTEA , '\x2998fa253a711f6585de13634b50e4b5c67646307cb903b8c3e6febba813937d'::BYTEA, 'salt', '2', '2'); -- password = password 

INSERT INTO
    accounts (aci, pni, aci_identity_key, pni_identity_key, phone_number, account_attr)
VALUES
    ('7db772c1-5ae2-4d25-9daf-025be34aa7b1', 'PNI:2328ef13-246b-4ff9-9baf-e28933d0bc02', '\x05698cb1d48597a7e4922b08a395a24d50dfc7a304ced4fab97dc3d2ef5d1444f8'::BYTEA, '\x05e06a8dccc1ab4d1a45a58e252b4e3fb95611c5e44dafc45b20090c450ad77256'::BYTEA, '87654321', '\x00010000000100000000000000000000000000000000'::BYTEA); -- keys have to start with 05 and be over 64 bytes

INSERT INTO 
    devices (owner, device_id, name, auth_token, salt, registration_id, pni_registration_id)
VALUES
    (2, '1', '\x1234'::BYTEA , '\x2998fa253a711f6585de13634b50e4b5c67646307cb903b8c3e6febba813937d'::BYTEA, 'salt', '3', '3'); -- password = password 
