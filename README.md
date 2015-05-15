MitmFuzzer
=============
MitmFuzzer for use with [MitmProxy](https://github.com/mitmproxy/mitmproxy)

 * Fuzzes HTTP requests/responses
 * Can intelligently inject fuzzing payloads based on content-type

Usage
=======

#### Fuzz HTTP Repsonses
`mitmproxy -s "fuzz.py --responses --payloads ./fuzzdb"`

#### Fuzz HTTP Requests
`mitmproxy -s "fuzz.py --requests --payloads ./fuzzdb"`
