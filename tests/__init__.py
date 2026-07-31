'''
Testing module for the Session Pro Backend, testing internal and public APIs.

The backend tests call the DB APIs directly to test the outcome on the tables in the database.
Each test (and each TestingContext) runs against a fresh, throwaway PostgreSQL database minted by
the `pg_database` fixture on an ephemeral cluster (see conftest.py).

The server tests spins up a local Flask instance as per
(https://flask.palletsprojects.com/en/stable/testing/#sending-requests-with-the-test-client) and
sends a request using the test client and we vet the request and response produced by hitting said
endpoint.
'''
