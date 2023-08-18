CREATE TABLE emails(
    email_id SERIAL PRIMARY KEY,
    email_address TEXT NOT NULL,
    verified BOOLEAN NOT NULL,
    created_at timestamp DEFAULT current_timestamp,
    last_updated timestamp DEFAULT current_timestamp
);

CREATE TYPE INVITE_STATUS AS ENUM ('SUCCESS', 'FAILED', 'PENDING');
CREATE TABLE onboarding_invites(
    invite_id SERIAL PRIMARY KEY,
    email_id INTEGER UNIQUE REFERENCES emails (email_id) ON DELETE CASCADE,
    status INVITE_STATUS NOT NULL,
    created_at timestamp DEFAULT current_timestamp,
    last_updated timestamp DEFAULT current_timestamp
);
CREATE INDEX email_idx ON onboarding_invites (email_id);