from scapy.all import *
import re
import ast
import json
import requests
import urllib.parse
def translate(encoded_string):
        
    hebrew_pattern = r'\\x([0-9A-Fa-f]{2})'

    # Find all Hebrew parts using regex
    hebrew_matches = re.findall(hebrew_pattern, encoded_string)
    # print('hebrew_matches:',hebrew_matches)
    hebrew = bytes.fromhex(''.join(hebrew_matches)).decode('utf-8')
    # print('decoded_hebrew',hebrew)
    split = encoded_string.split("\\x")
    if len(split) > 1:

        start = split[0]
        end = split[-1][2:] 
        new_url = start+ hebrew+end
    else:
        new_url = encoded_string
    return new_url
# Print the dictionary.
def custom_icmp_response(pkt):
    """
    A Scapy function that writes "custom message" on each ICMP response that my PC responds to.

    Args:
        pkt: A Scapy ICMP packet.

    Returns:
        A Scapy ICMP packet with the custom message written on it.
    """
    print('icmp')
    # Check if the packet is an ICMP Echo Request (type 8) and if it is coming to your PC.
    if ICMP in pkt and pkt[ICMP].type == 8 :
        # Create a new ICMP Echo Reply (type 0) packet as a response.
        original_payload = bytes(pkt[ICMP].payload)
        try:
        # Convert the ICMP payload to a string
            request_str = str(pkt[Raw].load)
            # Split the request_str into its constituent parts
            parts = request_str.split('@#$%')
            method, url, headers_str, content = parts


            # Decode the URL-encoded string
            url = translate(url)
            if method[2]=='$':  #my client identification
                method = method[3:]
                if method == 'POST':
                    content =json.loads( content[3:-3])
                    print(2)
                header_content = re.search(r'Headers\[(.*?)\]', headers_str).group(1)
                header_list = [pair.strip("()'") for pair in header_content.split('), (')]
                # print('header_list:',header_list)
                # print('headers:',header_dict)
                header_dict = {pair[2:pair.find(',')-1]:pair[pair.find(',')+4:].strip() for pair in header_list}
    
                verify_cert = 'mitmproxy-ca-cert.p12'
                msg='error or something'
                if method == "POST":
                    pass
                    http_response = requests.post(url, headers=header_dict, data=content, verify=verify_cert)
                elif method == "GET":
                    print('getting...')
                    http_response = requests.get(url, headers=header_dict, verify=verify_cert)
                    print('response:',http_response.status_code,http_response.text)
                if http_response.status_code == 200:
                    response_headers_dict = dict(http_response.headers)
                    # Serialize the dictionary to a JSON-formatted string
                    json_headers = json.dumps(response_headers_dict, ensure_ascii=False)
                    msg = '{}@#$%{}@#$%{}'.format(http_response.status_code,json_headers, http_response.text)
                response_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)

                # Modify the response payload to include the original data plus "hello".
                custom_message = original_payload + b"hello"
                response_pkt /= msg

                # Send the response packet.
                send(response_pkt, verbose=False)
        except Exception as e:
            print("Error:", e)
          
sniff(filter="icmp",iface="Software Loopback Interface 1", prn=custom_icmp_response)        #change or remove the interface when outside the pc
