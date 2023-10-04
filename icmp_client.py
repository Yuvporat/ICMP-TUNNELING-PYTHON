"""Send a reply from the proxy without sending the request to the remote server."""
from mitmproxy import http
from scapy.all import ICMP, IP, sr1, Raw
import requests
import json
def send_ICMP(dst_ip,message):
# Create an IP packet with the destination IP address
    packet = IP(dst=dst_ip) / ICMP(type=8, code=0) / message.encode()  # Echo Request (ping)
    # Send the packet with a short timeout (e.g., 1 second)             make bigger if its not working!
    response = sr1(packet, timeout=1)
    return response

def request(flow: http.HTTPFlow) -> None:
        
        server_ip = flow.request.host           #change to server ip!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        server_ip = '127.0.0.1'

        method = flow.request.method  # HTTP method (e.g., GET, POST)
        url = flow.request.url  # Full URL of the request
        headers = flow.request.headers  # Request headers
        content = flow.request.content  # Request content (e.
        request_str = '${}@#$%{}@#$%{}@#$%{}'.format(method, url, headers, content)
        # with open('icmp.txt', "w") as file:
        #         file.write(request_str)


        #send ICMP
        response = send_ICMP(server_ip,request_str)                 
        if response and response.haslayer(Raw):
            icmp_data = response[Raw].load
            content = icmp_data
            status = 200
            headers = {"Content-Type": "text/html"}

            # with open('icmp.txt', "w") as file:
            #     file.write(icmp_data.decode('utf-8'))
            """
            DONT DELETE IT!!!
            this is an example of parsing a response

            change it to:
                msg_data = icmp_data
            """
            # with open('haruz.txt', 'r', encoding='utf-8') as file:
            #     file_content = file.read()
            # msg_data = file_content
            # data_split = msg_data.split('@#$%')
            # status = int(data_split[0])
            # headers = json.loads(data_split[1])
            # content = data_split[2]
            """
            DONT DELETE!!!
            """




            

        else:
             content = "no response"
             status = 404
             
        #modify the response later
        #!!!
        flow.response = http.Response.make(
            status,  # (optional) status code
            content=str(content),  # (optional) content
            headers=headers  # (optional) headers
        )
        #!!!

# mitmproxy -s icmp_client.py