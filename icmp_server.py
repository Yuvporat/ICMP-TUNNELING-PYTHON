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
                    # print(2)
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

                reply_packet = IP(dst=packet[IP].src, src=packet[IP].dst) / ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)

                # Set the payload of the reply packet to the custom message
                reply_packet /= msg

                # Print the modified reply packet
                print("Modified ICMP Reply Packet:")
                print(reply_packet.show())
                # Send the modified reply packet using Scapy's socket
                send(reply_packet)
        except Exception as e:
            print("Error:", e)


        # Create an ICMP Echo Reply packet with custom data
        # reply = IP(src=pkt[IP].dst, dst=pkt[IP].src) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / "Custom Data"
        # send(reply)
# def modify_icmp_packet(pkt):
#     # Check if the packet is an ICMP echo request
#     if ICMP in pkt and pkt[ICMP].type == 8 and pkt[IP].src:
#         # Modify the ICMP echo reply payload
#         print(1)
#         print(type(pkt[ICMP]),pkt[ICMP].payload)
#         pkt[ICMP].payload = 'heloooooooooooooow'
# def modify_icmp_packet(pkt):
#     # Check if the packet is an ICMP echo request
#     if ICMP in pkt and pkt[ICMP].type == 8 and pkt[IP].src:
#         # Modify the ICMP echo reply payload

#         # Convert the ICMP payload to a Scapy packet
#         icmp_payload = scapy.Raw(pkt[ICMP].payload)
#         print('icmp_payload:',icmp_payload)
#         # Modify the ICMP payload packet
#         icmp_payload.payload = 'heloooooooooooooow'

#         # Set the ICMP payload packet back to the original packet
#         pkt[ICMP].payload = icmp_payload

#     return pkt
def modify_icmp_packet(pkt):
    # Check if the packet is an ICMP echo request
    if ICMP in pkt and pkt[ICMP].type == 8 and pkt[IP].src:
        # Modify the ICMP echo reply payload

        # Convert the ICMP payload to bytes
        icmp_payload = bytes(pkt[ICMP].payload)

        # Modify the ICMP payload
        new_payload = Raw(load="Modified Reply")

        # Calculate the new checksum for the modified payload
        checksum = pkt[ICMP].chksum
        checksum -= checksum_bytes(icmp_payload)
        checksum += checksum_bytes(new_payload)
        checksum %= 0xFFFF

        # Update the ICMP payload and checksum
        pkt[ICMP].payload = new_payload
        pkt[ICMP].chksum = checksum

        # Provide a custom summary for the packet
        pkt.custom_summary = "Modified ICMP Packet"

    return pkt
def modify_icmp_packet(pkt):
    # Check if the packet is an ICMP echo request
    if ICMP in pkt and pkt[ICMP].type == 8 and pkt[IP].src:
        # Modify the ICMP echo reply payload

        # Convert the ICMP payload to bytes
        icmp_payload = bytes(pkt[ICMP].payload)
        print('icmp_payload:', icmp_payload)

        pkt[ICMP].payload = Raw(load="Modified Reply")
        # # Modify the ICMP payload
        # new_payload = b'heloooooooooooooow'

        # # Calculate the new checksum for the modified payload
        # checksum = pkt[ICMP].chksum
        # checksum -= checksum_bytes(icmp_payload)
        # checksum += checksum_bytes(new_payload)
        # checksum %= 0xFFFF

        # # Update the ICMP payload and checksum
        # pkt[ICMP].payload = new_payload
        # pkt[ICMP].chksum = checksum

        # # Provide a custom summary for the packet
        # pkt.custom_summary = "Modified ICMP Packet"

    return pkt

def checksum_bytes(data):
    # Calculate the checksum for a bytes-like object
    checksum = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            checksum += (data[i] << 8) + data[i + 1]
        else:
            checksum += (data[i] << 8)
    while checksum > 0xFFFF:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def modify_and_send_icmp_reply(packet):
    if ICMP in packet and packet[ICMP].type == 8:  # Check for ICMP echo request (type 8)
        # Modify the payload of the received ICMP packet
        icmp_packet = packet[ICMP]
        icmp_packet.payload = Raw(load="Modified Reply")

        # Swap source and destination IP addresses
        packet[IP].src, packet[IP].dst = packet[IP].dst, packet[IP].src

        # Change ICMP type to echo reply (type 0)
        icmp_packet.type = 0

        # Calculate the ICMP checksum
        del icmp_packet.chksum
        icmp_packet.chksum = 0  # Recalculate the checksum

        # Send the modified ICMP reply
        send(packet)

# Packet handling function
def packet_handler(packet):
    if ICMP in packet:
        modify_and_send_icmp_reply(packet)
def custom_icmp_responder0(pkt):
    if ICMP in pkt and pkt[ICMP].type == 0 :
        print("Received ICMP Echo Request")
        icmp_payload = bytes(pkt[ICMP].payload)
        print('icmp_payload:',icmp_payload)
        # Modify the ICMP payload
        new_payload = Raw(load="Modified Reply")
        pkt[ICMP].payload = new_payload
        return pkt
def custom_icmp_responder(pkt):
    if ICMP in pkt and pkt[ICMP].type == 0:  # ICMP Echo Request
        print("Received ICMP Echo Request")
        icmp_payload = bytes(pkt[ICMP].payload)
        print('icmp_payload:', icmp_payload)
        
        # Modify the ICMP payload
        new_payload = Raw(load="Modified Reply")
        # response_pkt = pkt[ICMP]
        # response_pkt.payload = new_payload
                
        response_pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / '*****hellowwwwwwww'
        # response_pkt=pkt[ICMP]
        # response_pkt.payload = new_payload
        send(response_pkt, verbose=False)
                # Send the response packet.
sniff(filter="icmp", prn=custom_icmp_responder)        #change or remove the interface when outside the pc
# sniff(filter="icmp",iface="Software Loopback Interface 1", prn=custom_icmp_response)        #change or remove the interface when outside the pc
