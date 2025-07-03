from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP, DNSQR
from datetime import datetime
import json
from threading import Timer
from collections import defaultdict

BLOCKED_IPS = {"192.168.1.10", "127.0.0.1"}
BLOCKED_PORTS = {22, 23}
BLOCKED_DOMAINS = {"facebook.com", "www.facebook.com", "ads.google.com", "reddit.com", "www.reddit.com"}
thread_flag = True
thread_flag1 = True

prt_lst = defaultdict(lambda: {"ports": set()})
THRESHOLD = 5

def ps_ob(src_addr):
    current_datetime = str(datetime.now())
    lg = {
        "IP ADDRESS": src_addr,
        "TIME": current_datetime,
    }
    with open("logs.json", "r+") as file:
        file_data = json.load(file)
        file_data["SSPC_IP"].append(lg)
        file.seek(0)
        json.dump(file_data, file, indent=4)

def clean_up():
    spc_ips = [ip for ip, data in prt_lst.items()
               if len(data["ports"]) > THRESHOLD
            ]
    for i in spc_ips:
        ps_ob(i)
        BLOCKED_IPS.add(i)
        print(f"{i} has been banned for the next 10 minutes")
    prt_lst.clear()
    if thread_flag == True:
        t = Timer(10, clean_up)
        t.start()

t = Timer(10, clean_up)
t.start()

def unban():
    BLOCKED_IPS.clear()
    if thread_flag1 == True:
        t = Timer(600, unban)
        t.start()

t1 = Timer(600, unban)
t1.start()

def js_ob(src_addr, status, prt):
    current_datetime = str(datetime.now())
    lg = {
        "IP ADDRESS": src_addr,
        "STATUS": status,
        "TIME": current_datetime,
        "PORT": prt
    }
    with open("logs.json", "r+") as file:
        file_data = json.load(file)
        file_data["IP_details"].append(lg)
        file.seek(0)
        json.dump(file_data, file, indent=4)

def dn_ob(src_addr, status, domain):
    current_datetime = str(datetime.now())
    lg = {
        "IP ADDRESS": src_addr,
        "STATUS": status,
        "TIME": current_datetime,
        "DOMAIN": domain
    }
    with open("logs.json", "r+") as file:
        file_data = json.load(file)
        file_data["DNS_details"].append(lg)
        file.seek(0)
        json.dump(file_data, file, indent=4)


def is_blocked(domain):
    return domain.lower() in BLOCKED_DOMAINS

def firewall(packet):
    scapy_pkt = IP(packet.get_payload())
    nm_IP = scapy_pkt[IP].src

    if nm_IP in BLOCKED_IPS:
        print("IP BLOCKED")
        packet.drop()
    else:
        if scapy_pkt.haslayer(DNSQR):
            qname = scapy_pkt[DNSQR].qname.decode().strip(".")
            src_ip = scapy_pkt[IP].src

            print(f"[DNS] Query for: {qname} from {src_ip}")
            if is_blocked(qname):
                dn_ob(src_ip,"BLOCKED", qname)
                print(f"[BLOCKED DNS] Domain: {qname} for {src_ip}")
                packet.drop()
                return
            else:
                pass

        if scapy_pkt.haslayer(ICMP):
            src_ip = scapy_pkt[IP].src
            if src_ip in BLOCKED_IPS:
                js_ob(src_ip, "BLOCKED", "NULL")
                print(f"[BLOCKED] ICMP packet from {scapy_pkt.src}")
                packet.drop()
                return
            else:
                pass

        if scapy_pkt.haslayer(TCP) or scapy_pkt.haslayer(UDP):
            proto = TCP if scapy_pkt.haslayer(TCP) else UDP
            src_ip = scapy_pkt[IP].src
            dst_port = scapy_pkt[proto].dport

            if src_ip in BLOCKED_IPS:
                js_ob(src_ip, "BLOCKED", "NULL")
                print(f"[BLOCKED] IP {src_ip}")
                packet.drop()
                return
            else:
                if scapy_pkt.haslayer(TCP):
                    src_ip = scapy_pkt[IP].src
                    dst_port = scapy_pkt[TCP].dport
                    if src_ip not in prt_lst:
                        prt_lst[src_ip]["ports"] = {dst_port}
                    else:
                        prt_lst[src_ip]["ports"].add(dst_port)

                elif scapy_pkt.haslayer(UDP):
                    src_ip = scapy_pkt[IP].src
                    dst_port = scapy_pkt[UDP].dport
                    if src_ip not in prt_lst:
                        prt_lst[src_ip]["ports"] = {dst_port}
                    else:
                        prt_lst[src_ip]["ports"].add(dst_port)

            if dst_port in BLOCKED_PORTS:
                    js_ob("NULL", "BLOCKED", dst_port)
                    print(f"[BLOCKED] Port {dst_port}")
                    packet.drop()
                    return
            else:
                pass
        
        packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, firewall)
try:
    print("Firewall  running. Press Ctrl+C to stop.")
    nfqueue.run()
except KeyboardInterrupt:
    print("")
    print("Stopping firewall.....")
    thread_flag = False
    thread_flag1 = False
nfqueue.unbind()