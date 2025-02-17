#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.dot11 import Dot11ProbeReq, Dot11Elt
import argparse
import sys

# Colores para la salida
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

detected_devices = {}

def print_banner():
    print(f"""{GREEN}
    ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
    ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
    ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
    ██╔═══╝ ██╔══██╗██║   ██║██╔═══╝ ██╔══╝  
    ██║     ██║  ██║╚██████╔╝██║     ███████╗
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝
    {RED}Wi-Fi History Sniffer{RESET}
    """)

def handle_probe(packet):
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
                print(f"{GREEN}[+]{RESET} {BLUE}Dispositivo:{RESET} {YELLOW}{mac}{RESET} {BLUE}Busca red:{RESET} {RED}{ssid}{RESET}")

def main(interface):
    print_banner()
    print(f"{MAGENTA}[*]{RESET} Iniciando sniffer en modo monitor...")
    print(f"{MAGENTA}[*]{RESET} Interface: {YELLOW}{interface}{RESET}")
    print(f"{MAGENTA}[*]{RESET} Presiona {RED}Ctrl+C{RESET} para detener\n")
    
    try:
        sniff(
            iface=interface,
            prn=handle_probe,
            store=0,
            monitor=True,
            filter="subtype probe-req"
        )
    except KeyboardInterrupt:
        print(f"\n{MAGENTA}[*]{RESET} Deteniendo sniffer...")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Detecta redes Wi-Fi a las que se han conectado dispositivos cercanos"
    )
    parser.add_argument(
        "-i", "--interface",
        required=True,
        help="Interfaz en modo monitor (ej: wlan0mon)"
    )
    args = parser.parse_args()
    main(args.interface)
