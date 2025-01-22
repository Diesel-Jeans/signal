CREATE TABLE accounts (
    id                INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    aci               VARCHAR(36) NOT NULL UNIQUE,
    pni               VARCHAR(40) NOT NULL UNIQUE,
    aci_identity_key  BYTEA NOT NULL,
    pni_identity_key  BYTEA NOT NULL,
    phone_number      TEXT NOT NULL UNIQUE
);

CREATE TABLE devices (
    id              INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner           INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id       TEXT NOT NULL,
    name            BYTEA NOT NULL,
    auth_token      TEXT NOT NULL,
    salt            TEXT NOT NULL,
    registration_id TEXT NOT NULL,
    pni_registration_id TEXT NOT NULL,
    UNIQUE(device_id, owner)
);

CREATE TABLE device_capabilities (
    id              INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    owner           INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    capability_type INTEGER NOT NULL
);

CREATE TABLE used_device_link_tokens (
    id              INTEGER PRIMARY KEY NOT NULL GENERATED ALWAYS AS IDENTITY,
    device_link_token TEXT NOT NULL UNIQUE
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
    accounts (aci, pni, aci_identity_key, pni_identity_key, phone_number)
VALUES
    ('0d76041e-54ce-4cea-a128-ebfa32171c29', 'PNI:93c5486c-5bba-437f-a9c1-0570cb619d27', '\x05ef3dac866da0ee931afcb9c5d698c440d97a188b44e330d03524efcc913ce168'::BYTEA, '\x05ac6107870a9675937f84e881260276f1a565f9d68805ec7305d7e7c5589f7573'::BYTEA, '12345678'); -- keys have to start with 05 and be over 64 bytes

INSERT INTO 
    devices (owner, device_id, name, auth_token, salt, registration_id, pni_registration_id)
VALUES
    (1, '1', '\x1234'::BYTEA ,'2998fa253a711f6585de13634b50e4b5c67646307cb903b8c3e6febba813937d' , 'salt', '1', '1'); -- password = password 

INSERT INTO 
    devices (owner, device_id, name, auth_token, salt, registration_id, pni_registration_id)
VALUES
    (1, '2', '\x5678'::BYTEA , '2998fa253a711f6585de13634b50e4b5c67646307cb903b8c3e6febba813937d', 'salt', '2', '2'); -- password = password 

INSERT INTO
    accounts (aci, pni, aci_identity_key, pni_identity_key, phone_number)
VALUES
    ('7db772c1-5ae2-4d25-9daf-025be34aa7b1', 'PNI:2328ef13-246b-4ff9-9baf-e28933d0bc02','\x05ef3dac866da0ee931afcb9c5d698c440d97a188b44e330d03524efcc913ce168'::BYTEA , '\x05ac6107870a9675937f84e881260276f1a565f9d68805ec7305d7e7c5589f7573'::BYTEA, '87654321'); -- keys have to start with 05 and be over 64 bytes

INSERT INTO 
    devices (owner, device_id, name, auth_token, salt, registration_id, pni_registration_id)
VALUES
    (2, '1', '\x1234'::BYTEA , '2998fa253a711f6585de13634b50e4b5c67646307cb903b8c3e6febba813937d', 'salt', '3', '3'); -- password = password 
    
