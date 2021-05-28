"""
Run a simple HTTP server which provides API endpoint for SFTPPlus.

Usage:
  server.py [options]

-h --help           Show this help.
-p --port=8000         Listen to a specific port.  [default: 8080]
-a --address=127.0.0.1 Listen on specific address.  [default: 0.0.0.0]
-c --certificate=PATH  Enable HTTPS by defining the path
                  to a file containing server key, certificate, and CA chain
                  all PEM format and stored in a single file.
-f --flaky  Introduce random errors to test SFTPPlus API retry functionality.

The following API endpoints are provided:

* /auth-api - For the authentication API
* /event-api - For the event handler API

"""
from __future__ import absolute_import, unicode_literals

import base64
import json
import ssl
from random import randint

from aiohttp import web
from docopt import docopt

# Command line handling part.
arguments = docopt(__doc__)
# Convert arguments to usable types.
port = int(arguments["--port"])
# Need to escape the address for ipv6.
address = arguments["--address"].replace(":", r"\:")
is_flaky = arguments["--flaky"]
certificate = arguments["--certificate"]


# Set to lower values to increase the probability of a failure.
_FLAKY_DEGREE = 3

# DB with accepted accounts.
# Each key is the name of an user.
# Each value contains the accepted password and/or SSH-key.
ACCOUNTS = {
    # An account with some custom configuration.
    # Configuration that is not explicitly defined here is extracted based on
    # the SFTPPlus group.
    "test-user": {
        "password": "test-pass",
        # Just the public key value, in OpenSSH format.
        # Without hte key type or comments.
        "ssh-public-key": "AAAAB3NzaC1yc2EAAAADAQABAAAAgQC4fV6tSakDSB6ZovygLsf1iC9P3tJHePTKAPkPAWzlu5BRHcmAu0uTjn7GhrpxbjjWMwDVN0Oxzw7teI0OEIVkpnlcyM6L5mGk+X6Lc4+lAfp1YxCR9o9+FXMWSJP32jRwI+4LhWYxnYUldvAO5LDz9QeR0yKimwcjRToF6/jpLw==",
        "configuration": {
            "home_folder_path": "/tmp",
            # EXTRA_DATA is not yet supported.
            # 'extra_data': {
            #    'file_api_token': 'fav1_some_value',
            # },
        },
    },
    # An account with default configuration extracted from
    # the default SFTPPlus group.
    # SSH-Key authentication is disabled for this user.
    "default-user": {
        "password": "default-pass",
        "ssh-public-key": "",
        "configuration": {},
    },
}


async def handle_root(request):
    return web.Response(text="Demo SFTPPlus API endpoints.")


async def handle_auth(request):
    """
    This is triggered for authentication API calls.
    """
    request_json = await get_json(request)
    print("\n\n")
    print("-" * 80)
    print("New authentication request received")
    print(json.dumps(request_json, indent=2))

    if is_flaky and randint(0, _FLAKY_DEGREE) == 0:
        print("TRIGGERING AN EMULATED FAILURE")
        return web.Response(status=500, text="Failed to process the request")

    credentials = request_json["credentials"]
    account = ACCOUNTS.get(credentials["username"], None)

    if account is None:
        # This is not an account handled by this authentication API.
        # Inform SFTPPus that it can try to authenticate the user via other
        # method (LDAP, or another HTTP authentication server).
        print("UNKNOWN USER")
        return web.Response(
            status=401, text="User not handled by our API. Try other method."
        )

    response = {"account": account.get("configuration", {})}

    if credentials["type"] in ["password", "password-basic-auth"]:
        # We have password based authentication.
        if credentials["content"] != account["password"]:
            print("INVALID PASSWORD")
            return web.Response(status=403, text="Password rejected.")

        # Valid password.
        print("VALID PASSWORD")
        return web.json_response(response)

    if credentials["type"] == "ssh-key":
        # We have SSH-key based authentication.
        # The keys are encoded as BASE64, but we compare them as bytes.
        if base64.b64decode(credentials["content"]) != base64.b64decode(
            account["ssh-public-key"]
        ):
            print("INVALID SSH-KEY")
            return web.Response(status=403, text="SSH-Key rejected.")

        # Valid SSH key authentication.
        print("VALID SSH-KEY")
        return web.json_response(response)

    return web.Response(status=403, text="Credentials type not supported.")


async def handle_event(request):
    """
    This is triggered by the event handler API calls.
    """
    print("\n\n")
    print("-" * 80)
    print("New event handler call")
    print("-" * 80)
    print("Headers:")
    for key, value in request.headers.items():
        print(f"  {key}: {value}")
    print("-" * 80)
    print("Payload:")
    await get_json(request)

    if is_flaky and randint(0, _FLAKY_DEGREE) == 0:
        print("TRIGGERING AN EMULATED FAILURE")
        return web.Response(status=500, text="Failed to process the request")

    # An empty response body can be used to confirm that the event
    # was received successfully by the API server.
    # This instruct SFTPPlus not to retry.
    return web.Response(status=204, text="")


async def get_json(request):
    """
    Return the json dict from `request`.

    It also logs the JSON
    """
    result = {}
    try:
        result = await request.json()
    except json.JSONDecodeError:
        print("INVALID JSON RECEIVED")
        text = await request.text()
        print(text)
        result = {}
    else:
        print(json.dumps(result, indent=2))

    return result


app = web.Application()
app.add_routes(
    [
        web.get("/", handle_root),
        web.post("/auth-api", handle_auth),
        web.post("/event-api", handle_event),
    ]
)


ssl_context = None
if certificate:
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_cert_chain(certificate, certificate)

if __name__ == "__main__":
    web.run_app(app, host=address, port=port, ssl_context=ssl_context)
