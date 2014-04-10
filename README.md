friendly-heartbleed
===================

A friendly (non-malicious) way to check heartbleed-style vulnerabilities.
Using the HeartBeat extension without a payload length will read at least 16bytes of memory.

Usage
-----
`python ./friendlytest.py <hostname>`

