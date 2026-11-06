
import re
import ipaddress
from urllib.parse import urlparse


# Warning signs and their risk scores
WARNING_SCORES = {
    "Contains the @ symbol.": 15,
    "URL is longer than 100 characters.": 10,
    "Uses an IP address instead of a domain name.": 20,
    "Hostname contains five or more parts.": 15,
    "Contains the 'xn--' punycode marker.": 20,
    "Uses HTTP instead of HTTPS.": 20
}


# Explanations for each warning sign
REASONS = {
    "Contains the @ symbol.":
        "The @ symbol can make a URL look misleading.",

    "URL is longer than 100 characters.":
        "Very long URLs can hide suspicious information.",

    "Uses an IP address instead of a domain name.":
        "Phishing websites may use IP addresses instead of normal domain names.",

    "Hostname contains five or more parts.":
        "Unusually long hostnames can imitate trusted websites.",

    "Contains the 'xn--' punycode marker.":
        "Punycode can make a fake domain look similar to a genuine domain.",

    "Uses HTTP instead of HTTPS.":
        "HTTP does not encrypt the connection."
}


# Safety tips for each warning sign
SAFETY_TIPS = {
    "Contains the @ symbol.":
        "Check the actual hostname carefully. Do not trust the name written before @.",

    "URL is longer than 100 characters.":
        "Avoid clicking unfamiliar long links. Check the complete address carefully.",

    "Uses an IP address instead of a domain name.":
        "Be cautious of links that use numbers instead of a familiar website name.",

    "Hostname contains five or more parts.":
        "Read the hostname from right to left and check the actual domain.",

    "Contains the 'xn--' punycode marker.":
        "Watch for lookalike characters and misspelled website names.",

    "Uses HTTP instead of HTTPS.":
        "Avoid entering sensitive information on unencrypted HTTP pages."
}


# Store scan history during the current session
scan_history = []


# Check whether the URL contains an IP address
def is_ip_address(host):

    try:
        ipaddress.ip_address(host)
        return True

    except ValueError:
        return False


# Analyse the URL
def inspect_url(raw_url):

    url = raw_url.strip()

    findings = []

    if not url:
        return None

    # Add HTTP if no protocol is entered
    candidate = url

    if "://" not in candidate:
        candidate = "http://" + candidate

    # Extract URL information
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()

    except ValueError:
        return None

    if not host:
        return None

    # Check 1: @ symbol
    if "@" in candidate:
        findings.append("Contains the @ symbol.")

    # Check 2: URL length
    if len(url) > 100:
        findings.append("URL is longer than 100 characters.")

    # Check 3: IP address
    if is_ip_address(host):
        findings.append(
            "Uses an IP address instead of a domain name."
        )

    # Check 4: Five or more hostname parts
    hostname_parts = host.split(".")

    if len(hostname_parts) >= 5:
        findings.append(
            "Hostname contains five or more parts."
        )

    # Check 5: Punycode marker
    if "xn--" in host:
        findings.append(
            "Contains the 'xn--' punycode marker."
        )

    # Check 6: HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        findings.append(
            "Uses HTTP instead of HTTPS."
        )

    # Calculate risk score
    risk_score = 0

    for item in findings:
        risk_score += WARNING_SCORES[item]

    # Get classification
    if risk_score <= 30:
        classification = "LOW RISK INDICATOR LEVEL"

    elif risk_score <= 60:
        classification = "MEDIUM RISK INDICATOR LEVEL"

    else:
        classification = "HIGH RISK INDICATOR LEVEL"

    # Extract domain information
    domain_parts = host.split(".")

    if len(domain_parts) >= 2:
        domain = ".".join(domain_parts[-2:])
    else:
        domain = host

    # Store URL details
    result = {
        "url": url,
        "protocol": parsed.scheme.upper(),
        "hostname": host,
        "domain": domain,
        "path": parsed.path if parsed.path else "/",
        "findings": findings,
        "score": risk_score,
        "classification": classification
    }

    return result


# Display URL breakdown
def display_breakdown(result):

    print("\n--- URL BREAKDOWN ---")

    print("Original URL:", result["url"])
    print("Protocol:", result["protocol"])
    print("Hostname:", result["hostname"])
    print("Domain:", result["domain"])
    print("Path:", result["path"])


# Display the risk score
def display_risk(result):

    print("\n--- RISK ASSESSMENT ---")

    print("Risk Score:", str(result["score"]) + "/100")
    print("Classification:", result["classification"])

    if result["score"] == 0:
        print("No selected warning signs were detected.")

    print("Note: This score is a simple awareness indicator,")
    print("not a prediction of whether a website is malicious.")


# Display warnings and explanations
def display_warnings(result):

    findings = result["findings"]

    print("\n--- WARNING SIGNS ---")

    if not findings:
        print("No listed warning signs found.")
        return

    for i, item in enumerate(findings, start=1):

        print("\n" + str(i) + ". " + item)
        print("Why it matters:", REASONS[item])


# Display personalised safety tips
def display_tips(result):

    print("\n--- SAFETY RECOMMENDATIONS ---")

    findings = result["findings"]

    if not findings:
        print("No selected warning signs were detected.")
        print("Still check the website address before entering")
        print("personal or financial information.")
        return

    for i, item in enumerate(findings, start=1):

        print(str(i) + ". " + SAFETY_TIPS[item])


# Display the complete URL analysis
def display_result(result):

    print("\n" + "=" * 50)
    print("             URL ANALYSIS REPORT")
    print("=" * 50)

    display_breakdown(result)

    display_warnings(result)

    display_risk(result)

    display_tips(result)

    print("\n" + "=" * 50)
    print("Remember: HTTPS does not automatically mean a")
    print("website is trustworthy.")
    print("=" * 50)


# Save the scan in session history
def save_scan(result):

    scan_history.append(result)


# Display previous scans
def show_history():

    print("\n--- SCAN HISTORY ---")

    if not scan_history:
        print("No URLs have been checked yet.")
        return

    for i, item in enumerate(scan_history, start=1):

        print("\nScan", i)
        print("URL:", item["url"])
        print("Risk Score:", str(item["score"]) + "/100")
        print("Classification:", item["classification"])


# Display scanning statistics
def show_statistics():

    print("\n--- SCAN STATISTICS ---")

    total = len(scan_history)

    if total == 0:
        print("No scans have been performed yet.")
        return

    flagged = 0
    clean = 0
    highest_score = 0

    for item in scan_history:

        if item["findings"]:
            flagged += 1
        else:
            clean += 1

        if item["score"] > highest_score:
            highest_score = item["score"]

    print("Total URLs checked:", total)
    print("URLs with warnings:", flagged)
    print("URLs without listed warnings:", clean)
    print("Highest risk score:", str(highest_score) + "/100")



def main():

    print("=" * 50)
    print("       PHISHING URL AWARENESS CHECKER")
    print("=" * 50)

    print("A simple tool to identify selected URL warning signs.")
    print("This program does not open websites or access the internet.")

    while True:

        print("\n" + "-" * 40)
        print("MAIN MENU")
        print("-" * 40)

        print("1. Check a URL")
        print("2. View scan history")
        print("3. View scan statistics")
        print("4. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":

            raw_url = input("\nEnter a URL: ")

            if raw_url.strip().lower() in ("q", "quit", "exit"):
                print("Returning to the main menu.")
                continue

            result = inspect_url(raw_url)

            if result is None:
                print("\nInvalid or empty URL. Please enter a valid URL.")
                continue

            display_result(result)
            save_scan(result)

        elif choice == "2":

            show_history()

        elif choice == "3":

            show_statistics()

        elif choice == "4":

            print("\nThank you for using the Phishing URL Awareness Checker!")
            print("Stay alert and stay safe online.")
            break

        else:

            print("\nInvalid choice. Please select 1, 2, 3 or 4.")


if __name__ == "__main__":
    main()
