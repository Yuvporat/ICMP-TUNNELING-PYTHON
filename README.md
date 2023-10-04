# ICMP-TUNNELING-PYTHON
ICMP tunneling between a client and a server, http requests and responses inside ICMP echo and reply data

Client:
*The client is Man In The Middle Proxy (mitmproxy)
*create and activate virtual enviroment
*pip instal -r requirements.txt
*mitmproxy -s icmp_client.py
*configure your pc to use mitmproxy as your proxy server, see https://docs.mitmproxy.org/stable/
*configure the client to send requests to the server IP
*for each http request, mitmproxy sends an ICMP echo request to the server, with the HTTP request in the data of the packet

Server:
*The server is a Scapy script
*It listens to ICMP requests, reads the data, converts it to HTTP request, sends the request, put the response in the ICMP reply data, and finally reply the ICMP

*In the end, the Client (mitmproxy) read the ICMP reply data, convert it to a HTTP response and return it to the consumer (like browser)