#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11Elt
import argparse
import sys
import subprocess
import time

# Colores para el output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"
detected_devices = {}
ssid_file = "essids.txt"  # Archivo donde se guardarán los SSID

def print_banner():
    print(fr"""{GREEN}{BOLD}
 __  __ _______ _______ ______
|  |/  |    |  |   _   |   __ \
|     <|       |       |    __/
|__|\__|__|____|___|___|___|

{RESET}{BLUE}Known Nearby Access Points{GREEN}{RESET}
""")


def is_monitor_mode(interface):
    try:
        output = subprocess.check_output(["iwconfig", interface],
                                         stderr=subprocess.STDOUT).decode("utf-8")
        return "Mode:Monitor" in output
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!]{RESET} Error while executing iwconfig: {e.output.decode('utf-8')}")
        return False

def load_existing_ssids():
    """Carga los SSIDs existentes en el archivo para evitar duplicados."""
    try:
        with open(ssid_file, "r") as f:
            return set(f.read().splitlines())  # Devuelve los SSID existentes
    except FileNotFoundError:
        return set()  # Si el archivo no existe, retorna una variable vacía

def load_oui(oui_file):
    oui_data = {}
    try:
        with open(oui_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    oui, vendor = parts
                    # Normalizamos el OUI a mayúsculas y con formato XX:XX:XX
                    if ":" not in oui and len(oui) == 6:
                        oui = ":".join(oui[i:i+2] for i in range(0,6,2))
                    else:
                        oui = oui.upper()
                    # Limpieza del nombre del fabricante
                    vendor = vendor.replace('(base 16)', '').replace('(', '').replace(')', '').strip()
                    oui_data[oui] = vendor
        return oui_data
    except Exception as e:
        print(f"{RED}[!]{RESET} Error al cargar el archivo OUI: {e}")
        return {}

def get_vendor_from_oui(mac, oui_data):
    """Obtiene el fabricante usando los primeros 3 octetos de la MAC."""
    parts = mac.split(':')
    if len(parts) >= 3:
        oui = ":".join(parts[:3]).upper()
        return oui_data.get(oui, "Unknown")
    else:
        return "Unknown"

def handle_probe(packet, existing_ssids, oui_data):
    if packet.haslayer(Dot11ProbeReq):
        mac = packet[Dot11].addr2.upper()
        ssid = None
        
        # Extraer SSID del Probe Request
        elt = packet.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID parameter
                try:
                    ssid = elt.info.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    ssid = "<SSID no decodificable>"
                break
            elt = elt.payload.getlayer(Dot11Elt)
        
        if ssid and ssid.strip() != "" and ssid != " ":
            if mac not in detected_devices:
                detected_devices[mac] = set()
            
            if ssid not in detected_devices[mac]:
                detected_devices[mac].add(ssid)
                if oui_data:
                    vendor = f" ({get_vendor_from_oui(mac, oui_data)})"
                else:
                    vendor = ""
                print(f"{GREEN}[+]{RESET} {YELLOW}{mac}{RESET}{vendor}{BLUE} probing for{RESET} {RED}{ssid}{RESET}")

                # Si el SSID no está en el archivo, lo escribimos
                if ssid not in existing_ssids:
                    with open(ssid_file, "a") as f:
                        f.write(f"{ssid}\n")
                    existing_ssids.add(ssid)


def main(interface, oui_data):
    existing_ssids = load_existing_ssids()  # Cargar los SSID existentes al inicio
    print_banner()

    print(f"{BOLD}{YELLOW}[i]{RESET} Checking everything is ok...\n")
    time.sleep(0.4)
    if is_monitor_mode(interface):
        time.sleep(0.2)
        print(f"{BOLD}{GREEN}[+]{RESET} Interface in monitor mode.")
    else:
        print(f"{RED}[!]{RESET} Interface not in monitor mode!")
        print(f"{YELLOW}[i]{RESET} Run {BLUE}airmon-ng start {interface}{RESET}")
        sys.exit(1)


    if oui_data:
        time.sleep(0.2)
        print(f"{BOLD}{GREEN}[+]{RESET} OUI database loaded.")
    else:
        time.sleep(0.2)
        print(f"{BOLD}{RED}[-]{RESET} OUI database not loaded! Vendors won't be shown. (-h for info)")

    time.sleep(0.2)
    print(f"{BOLD}{GREEN}[+]{RESET} Interface: {YELLOW}{interface}{RESET}")
    time.sleep(0.2)
    print(f"{BOLD}{GREEN}[+]{RESET} Sniffing nearby probes...")
    print(f"{YELLOW}{BOLD}---------------------------------------------------{RESET}\n")
    try:
        sniff(
            iface=interface,
            prn=lambda pkt: handle_probe(pkt, existing_ssids, oui_data),
            store=0,
            monitor=True,
            filter="subtype probe-req"
        )
    except KeyboardInterrupt:
        print(f"\n{RED}[!]{RESET} QUITTING!...") 
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tool to sniff known nearby access points using probes sent by devices to retrieve the ESSIDs"
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Monitor mode interface (f.e: wlan0mon)"
    )
    parser.add_argument(
        "-oui", "--oui-file",
        dest="oui_file",
        help="Path to the OUI file (f.e., /home/kali/knap/oui.txt)",
        default=None
    )
    args = parser.parse_args()
    
    oui_data = None
    if args.oui_file:
        oui_data = load_oui(args.oui_file)
    
    main(args.interface, oui_data)
