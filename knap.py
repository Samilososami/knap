#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11Elt
import argparse
import sys

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

    {GREEN}Known Nearby Access Points{RESET}
    """)

def load_existing_ssids():
    """Carga los SSIDs existentes en el archivo para evitar duplicados."""
    try:
        with open(ssid_file, "r") as f:
            return set(f.read().splitlines())  # Devuelve los SSID existentes
    except FileNotFoundError:
        return set()  # Si el archivo no existe, retorna una variable vacía

def handle_probe(packet, existing_ssids):
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
                print(f"{GREEN}[+]{RESET} {YELLOW}{mac}{RESET}{BLUE} probing for{RESET} {RED}{ssid}{RESET}")

                # Si el SSID no está en el archivo, lo escribimos
                if ssid not in existing_ssids:
                    with open(ssid_file, "a") as f:
                        f.write(f"{ssid}\n")
                    existing_ssids.add(ssid)  # Añadir el SSID al conjunto para futuras verificaciones

def main(interface):
    existing_ssids = load_existing_ssids()  # Cargar los SSID existentes al inicio
    print_banner()
    print(f"{MAGENTA}[*]{RESET} Sniffing nearby probes...")
    print(f"{MAGENTA}[*]{RESET} Interface: {YELLOW}{interface}{RESET}")
    print(f"{MAGENTA}[*]{RESET} {RED}Ctrl+C{RESET} to stop\n")
    
    try:
        sniff(
            iface=interface,
            prn=lambda pkt: handle_probe(pkt, existing_ssids),
            store=0,
            monitor=True,
            filter="subtype probe-req"
        )
    except KeyboardInterrupt:
        print(f"\n{RED}[!]{RESET} QUITTING!...")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Tool to sniff known nearby access points using probes send by devices to retrieve the ESSIDs"
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Monitor mode interface (f.e: wlan0mon)"
    )
    args = parser.parse_args()
    main(args.interface)
