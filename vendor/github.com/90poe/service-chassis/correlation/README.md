## Correlation IDs

Correlation ID's are generated at the edge of the system when processing a request from a user agent and
are passed around the system and included in log output so that via logs the entire lifecycle of a request can be traced through services.

This package simply wraps calls to set and retrieve correlations ID's from context

