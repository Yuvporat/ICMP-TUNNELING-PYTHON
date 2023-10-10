from scapy.all import conf, send, sniff, Raw
from scapy.layers.inet import IP, ICMP
import win32com.client
import re
import ast
import json
import requests
import urllib.parse





#no need
SERVER_IP = '192.168.1.122'
custom_message = b'Custom ICMP Response Message'  # Use 'b' to indicate a bytes literal

def modify_icmp_packet(packet):
    if ICMP in packet and packet[ICMP].type == 8:  # Check if it's an ICMP Echo Request (type 8)
        # Create a new ICMP Echo Reply packet (type 0) based on the received Echo Request
        src = packet[IP].dst
        src = SERVER_IP
        reply_packet = IP(dst=packet[IP].src, src=src) / ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)

        # Set the payload of the reply packet to the custom message
        reply_packet /= custom_message

        # Print the modified reply packet
        print("Modified ICMP Reply Packet:")
        print(reply_packet.show())

        # Send the modified reply packet using Scapy's socket
        send(reply_packet)


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
                if method == "GET":
                    http_response = requests.get(url, headers=header_dict)
                    if http_response.status_code == 200:
                        
                        response_headers_dict = dict(http_response.headers)
                        json_headers = json.dumps(response_headers_dict, ensure_ascii=False)
                        body = http_response.text# Define the content for the <h3> tag
                        ### if html add newval
                        h3_content = "This is an H3 tag"

                        # Find the position of the closing </html> tag
                        html_end_pos = body.rfind("</body>")

                        if html_end_pos != -1:
                            # Insert the <h3> tag right before the </html> tag
                            body = body[:html_end_pos] + f"<h3>{h3_content}</h3>" + body[html_end_pos:]

                        ###
                        msg = '{}@#$%{}@#$%{}'.format(http_response.status_code,json_headers, body)
                        
                # if method == "POST":
                #     pass
                #     http_response = requests.post(url, headers=header_dict, data=content, verify=verify_cert)
                # elif method == "GET":
                #     print('getting...')
                #     http_response = requests.get(url, headers=header_dict, verify=verify_cert)
                #     print('response:',http_response.status_code,http_response.text)
                # if http_response.status_code == 200:
                #     response_headers_dict = dict(http_response.headers)
                #     # Serialize the dictionary to a JSON-formatted string
                #     json_headers = json.dumps(response_headers_dict, ensure_ascii=False)
                #     msg = '{}@#$%{}@#$%{}'.format(http_response.status_code,json_headers, http_response.text)
                        reply_packet = IP(dst=pkt[IP].src, src=pkt[IP].dst) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)

                        # Set the payload of the reply packet to the custom message
                        msg_length= len(msg.encode())
                        if msg_length > 1450:
                            #response error msg
                            msg = 'response to big... {} bytes'.format(msg_length)
                        reply_packet /= msg

                        # Print the modified reply packet
                        # print("Modified ICMP Reply Packet:")
                        print(reply_packet.show())
                        # Send the modified reply packet using Scapy's socket
                        send(reply_packet)
        except Exception as e:
            #return icmp reply with error http response
            print("Error:", e)

# Function to enable the Windows Firewall rule
def enable_firewall_rule(rule_name):
    try:
        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        rule = fw.Rules.Item(rule_name)
        rule.Enabled = True
        print(f"Firewall rule '{rule_name}' has been enabled.")
    except Exception as e:
        print(f"Error enabling firewall rule: {e}")

# Function to disable the Windows Firewall rule
def disable_firewall_rule(rule_name):
    try:
        fw = win32com.client.Dispatch("HNetCfg.FwPolicy2")
        rule = fw.Rules.Item(rule_name)
        rule.Enabled = False
        print(f"Firewall rule '{rule_name}' has been disabled.")
    except Exception as e:
        print(f"Error disabling firewall rule: {e}")




# Define the name of the firewall rule you want to manage
firewall_rule_name = "newval block icmp"

try:
    # Enable the firewall rule when the script starts
    enable_firewall_rule(firewall_rule_name)
    sniff(filter="icmp and icmp[0] == 8", prn=custom_icmp_response, store=False)

    # Your script logic here
    print("Your script is running...")
finally:
    # Disable the firewall rule when the script ends
    disable_firewall_rule(firewall_rule_name)
    print("Your script has finished.")