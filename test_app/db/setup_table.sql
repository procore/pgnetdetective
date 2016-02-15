CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE apple_picker (
    id uuid PRIMARY KEY NOT NULL DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    apples_picked INTEGER NOT NULL
);
