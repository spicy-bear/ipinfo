import requests
import json
from shodan import Shodan
from dotenv import load_dotenv
import os 

load_dotenv()
grey_api_key = os.environ.get('grey_api_key')
shodan_api_key = os.environ.get('shodan_api_key')
shodan = os.environ.get('shodan')
virustotal_key = os.environ.get('virustotal_key')
censys_api = os.environ.get('censys_api')

ip_address = input("ip address ")

title = r"""
 ▄▄▄ ▄▄▄▄▄▄▄    ▄▄▄▄▄▄ ▄▄▄▄▄▄  ▄▄▄▄▄▄  ▄▄▄▄▄▄   ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ 
█   █       █  █      █      ██      ██   ▄  █ █       █       █       █
█   █    ▄  █  █  ▄   █  ▄    █  ▄    █  █ █ █ █    ▄▄▄█  ▄▄▄▄▄█  ▄▄▄▄▄█
█   █   █▄█ █  █ █▄█  █ █ █   █ █ █   █   █▄▄█▄█   █▄▄▄█ █▄▄▄▄▄█ █▄▄▄▄▄ 
█   █    ▄▄▄█  █      █ █▄█   █ █▄█   █    ▄▄  █    ▄▄▄█▄▄▄▄▄  █▄▄▄▄▄  █
█   █   █      █  ▄   █       █       █   █  █ █   █▄▄▄ ▄▄▄▄▄█ █▄▄▄▄▄█ █
█▄▄▄█▄▄▄█      █▄█ █▄▄█▄▄▄▄▄▄██▄▄▄▄▄▄██▄▄▄█  █▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█
"""

print("")
###greynoise
print("#Greynoise Details#")

grey_headers = {
    'accept': 'application/json',
    'content-type': 'application/json',
    'key': grey_api_key
}

grey_response = requests.get(f"https://api.greynoise.io/v3/community/{ip_address}", headers=grey_headers)

if grey_response.status_code == 200:
    # The request was successful
    print(grey_response.text)

elif grey_response.status_code == 400:
    print(f"Greynoise Error: {grey_response.status_code}, Invalid Request")

elif grey_response.status_code == 401:
    print(f"Greynoise Error: {grey_response.status_code}, Authentication Error")

elif grey_response.status_code == 404:
    print(f"Greynoise Error: {grey_response.status_code}, IP Not Found in GreyNoise")

elif grey_response.status_code == 429:
    print(f"Greynoise Error: {grey_response.status_code}, Daily Rate-Limit Exceeded")

else:
    # There was an error with the request
    print(f"Greynoise Error: {grey_response.status_code}")



print("")
###shodan
print("#Shodan Details#")

shodan_response = requests.get(f"https://api.shodan.io/shodan/host/{ip_address}?key="+shodan_api_key)

# Parse the response into a dictionary
shodan_data = json.loads(shodan_response.text)

# Access the city, OS, ISP, ports, and hostnames
shodan_city = shodan_data["city"]
shodan_os = shodan_data["os"]
shodan_isp = shodan_data["isp"]
shodan_ports = shodan_data["ports"]
shodan_hostnames = shodan_data["hostnames"]

# Print the city, OS, ISP, ports, and hostnames
print("City:", shodan_city)
print("OS:", shodan_os)
print("ISP:", shodan_isp)
print("Ports:", shodan_ports)
print("Hostnames:", shodan_hostnames)


if shodan_response.status_code == 200:
    # The request was successful
#    json_data = shodan_response.text
#    json_object = json.loads(json_data)
#    json_formatted_str = json.dumps(json_object, indent=2)
#    print(json_formatted_str)
#    print(shodan_response.text)
    print("")

else:
    # There was an error with the request
    print(f"Shodan Error: {shodan_response.status_code}")



print("")
###censys
print("#Censys Details#")

censys_headers = {
    'accept': 'application/json',
    'Authorization': "Basic "+censys_api
}

censys_response = requests.get(f"https://search.censys.io/api/v2/hosts/{ip_address}",headers=censys_headers)

censys_data = json.loads(censys_response.text)

censys_ip = censys_data["result"]["ip"]
print("IP address:", censys_ip)

#ports = [service["port"] for service in data["result"]["services"]]
censys_services = censys_data["result"]["services"]
for service in censys_services:
    censys_port = service["port"]
    censys_port_service = service["service_name"]
#    os = service["software"][0]["product"]
#    hostnames = service["hostnames"]
#    dns_names = service["dns_names"]
    print("Port:", censys_port)
    print("Service:", censys_port_service)
#    print("Operating system:", os)
#    print("Hostnames:", hostnames)
#    print("DNS names:", dns_names)

# Print the IP address and port numbers
#print("IP address:", ip)
#print("Port numbers:", ports)

if censys_response.status_code == 200:
    #print(censys_response.text)
    print("")
# The request was successful
#    json_data = censys_response.text
#    json_object = json.loads(json_data)
#    json_formatted_str = json.dumps(json_object, indent=2)
#    print(json_formatted_str)

elif censys_response.status_code == 422:
    print("Invalid IP address")

elif censys_response.status_code == 429:
    print("Too many requests")

else:
    print(f"Censys Error: {censys_response.status_code}")


print("")
###virustotal
print("#VirusTotal Details#")

virustotal_headers = {
    'accept': 'application/json',
    'x-apikey': virustotal_key
}

virustotal_response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", headers=virustotal_headers)

#print(virustotal_response.text)
# Parse the JSON string into a dictionary
virustotal_json_data = json.loads(virustotal_response.text)

# Access the values associated with the keys "ip", "port", "service_name", and "os"
# and store them in variables
virustotal_ip = virustotal_json_data["data"]["attributes"]["network"]
virustotal_last_analysis_stats = virustotal_json_data["data"]["attributes"]["last_analysis_stats"]
#virustotal_service_name = virustotal_json_data["result"]["services"][0]["service_name"]
#virustotal_os = virustotal_json_data["result"]["services"][0]["software"][2]["product"]

# Print the values
print(f"IP: {virustotal_ip}")
print(f"Port: {virustotal_last_analysis_stats}")
#print(f"Service name: {virustotal_service_name}")
#print(f"Operating system: {virustotal_os}")
