# A connector between WebTrit and external VoIP system or PBX
## Overview
This is an application that serves as a mapper of API requests
from WebTrit cloud back-end to a 3rd-party system (e.g. hosted PBX)
to retrieve the data about users, so they can use WebTrit's
mobile or web dialer.

The idea is to expand it with additional modules for conecting to
specific types of systems.

More details about how (and why) WebTrit connects to external VoIP
or BSS systems in this [blog article](https://webtrit.com/insights/webrtc-softphone-third-party-voip-switches-cloud-pbx-systems/)

## What's included
* general FastAPI application that processes API requests from WebTrit
* bss/connectors/example.py module which mimics the functionality of
connecting to a real system. User info is stored in the source code and 
info about other extensions or previously made calls is generated randomly.
* set of tests (in tests/ folder) which you can use to test your own 
adapter once it is ready
* Dockerfile for packaging

## Usage
### With an "example" module
* cd app
* docker build -t xyz .
* make your container running on a public IP address (I assume 1.2.3.4)
* Verify that things are working on by
pytest --server http://1.2.3.4 tests
* Apply http://1.2.3.4 in the configuration of your WebTrit instance, so it
sends requests to your API

to an external
An example API adapter (Python/FastAPI) that allows to connect WebTrit to an external VoIP system and BSS
