sftpplus-api-example
====================

This is simple HTTP server that exposes the HTTP API endpoints consumed by
SFTPPlus.

It can be used as testing / proof of concenpt example to help undertand the
operation of SFTPPlus API.

Requirements:

* Python 3.9

Create the run environment::

    # First create a Python virtual environment.
    virtualenv venv
    # Then activate it.
    source venv/bin/activate
    # Install the required libraries.
    pip install -r requirements

To start the server just run::

    python api-server.py

Check command line options::

    python api-server.py --help

You can generate a new self-signed certificate using::

    openssl req -x509 -newkey rsa:2048 -nodes  -days 365 \
        -keyout server-key.pem \
        -out server-cert.pem
    cat server-key.pem server-cert.pem  > server-key-and-cert.pem
    rm server-key.pem server-cert.pem

To start the API server in HTTPS mode use::

    python api-server.py --certificate server-key-and-cert.pem
