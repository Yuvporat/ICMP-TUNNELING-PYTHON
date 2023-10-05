import win32com.client
import time
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
    
    # Your script logic here
    print("Your script is running...")
    time.sleep(10)

finally:
    # Disable the firewall rule when the script ends
    disable_firewall_rule(firewall_rule_name)
    print("Your script has finished.")

# Rest of your script here
