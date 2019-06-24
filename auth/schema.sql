-- Initialize the database.
-- Drop any existing data and create empty tables.

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS records;
DROP TABLE IF EXISTS recordValueStore;
DROP TABLE IF EXISTS recordTagGroups;

CREATE TABLE users (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    UNIQUE(username)--, -- this will ensure that each user is unique.
--    UNIQUE(username, password) -- this will ensure that users cannot
);

INSERT INTO users(ID, username, password) VALUES (0, 'JohnDoe', 'pass');
INSERT INTO users(ID, username, password) VALUES (1, 'MatthewRaison', 'ThisIsMyPassword');


-- This isn't actually used anymore...