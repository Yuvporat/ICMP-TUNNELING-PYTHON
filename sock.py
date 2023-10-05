from scapy.all import conf, send, sniff, Raw
from scapy.layers.inet import IP, ICMP
import win32com.client


custom_message = b'Custom ICMP Response Message'  # Use 'b' to indicate a bytes literal

def modify_icmp_packet(packet):
    if ICMP in packet and packet[ICMP].type == 8:  # Check if it's an ICMP Echo Request (type 8)
        # Create a new ICMP Echo Reply packet (type 0) based on the received Echo Request
        src = packet[IP].dst
        src = '69.69.69.69'
        reply_packet = IP(dst=packet[IP].src, src=src) / ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)

        # Set the payload of the reply packet to the custom message
        reply_packet /= custom_message

        # Print the modified reply packet
        print("Modified ICMP Reply Packet:")
        print(reply_packet.show())

        # Send the modified reply packet using Scapy's socket
        send(reply_packet)


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
    sniff(filter="icmp and icmp[0] == 8", prn=modify_icmp_packet, store=False)

    # Your script logic here
    print("Your script is running...")
finally:
    # Disable the firewall rule when the script ends
    disable_firewall_rule(firewall_rule_name)
    print("Your script has finished.")