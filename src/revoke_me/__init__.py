"""revoke-me: revoke leaked tokens from the command line.

Sends the token only to the provider's own revoke/info endpoints.
The token is read via getpass (hidden) and never logged or persisted.
"""

__version__ = "1.0.0"
