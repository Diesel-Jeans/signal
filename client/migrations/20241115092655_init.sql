CREATE TABLE DeviceIdentityKeyStore (
  id            INTEGER PRIMARY KEY,
  address       TEXT NOT NULL UNIQUE,
  identity_key  TEXT NOT NULL
);

CREATE TABLE DevicePreKeyStore (
  id              INTEGER PRIMARY KEY,
  pre_key_id      UNSIGNED BIG INT NOT NULL UNIQUE,
  pre_key_record  TEXT NOT NULL
);

CREATE TABLE DeviceSignedPreKeyStore (
  id                      INTEGER PRIMARY KEY,
  signed_pre_key_id       UNSIGNED BIG INT NOT NULL UNIQUE,
  signed_pre_key_record   TEXT NOT NULL
);

CREATE TABLE DeviceKyberPreKeyStore (
  id                    INTEGER PRIMARY KEY,
  kyber_pre_key_id      UNSIGNED BIG INT NOT NULL UNIQUE,
  kyber_pre_key_record  TEXT NOT NULL
);

CREATE TABLE DeviceSessionStore (
  id              INTEGER PRIMARY KEY,
  address         TEXT NOT NULL UNIQUE,
  session_record  TEXT NOT NULL
);

CREATE TABLE DeviceSenderKeyStore (
  id                  INTEGER PRIMARY KEY,
  address             TEXT NOT NULL UNIQUE,
  sender_key_record   TEXT NOT NULL
);

CREATE TABLE DeviceProtocolStore (
  id                    INTEGER PRIMARY KEY,
  identity_key_store    INTEGER NOT NULL REFERENCES DeviceIdentityKeyStore(id) ON DELETE CASCADE,
  pre_key_store         INTEGER NOT NULL REFERENCES DevicePreKeyStore(id) ON DELETE CASCADE,
  signed_pre_key_store  INTEGER NOT NULL REFERENCES DeviceSignedPreKeyStore(id) ON DELETE CASCADE,
  kyber_pre_key_store   INTEGER NOT NULL REFERENCES DeviceKyberPreKeyStore(id) ON DELETE CASCADE,
  session_store         INTEGER NOT NULL REFERENCES DeviceSessionStore(id) ON DELETE CASCADE,
  sender_key_store      INTEGER NOT NULL REFERENCES DeviceSenderKeyStore(id) ON DELETE CASCADE
);
