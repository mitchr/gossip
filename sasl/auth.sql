CREATE TABLE IF NOT EXISTS sasl_plain(
	username TEXT,
	pass BLOB,
	PRIMARY KEY(username)
);

CREATE TABLE IF NOT EXISTS sasl_external(
	username TEXT,
	clientCert BLOB,
	PRIMARY KEY(username)
);

CREATE TABLE IF NOT EXISTS sasl_scram(
	username TEXT,
	serverKey BLOB,
	storedKey BLOB,
	salt BLOB,
	iterations INTEGER,
	PRIMARY KEY(username)
);
