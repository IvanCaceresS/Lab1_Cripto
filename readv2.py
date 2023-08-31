import sys
import scapy.all as scapy
from colorama import init, Fore, Style
# Inicializar colorama
init(autoreset=True)
# Obtener la ruta del archivo .pcapng desde la línea de comandos
pcapng_file = sys.argv[1]
# Cargar el archivo .pcapng y filtrar los paquetes ICMP Request
packets = scapy.rdpcap(pcapng_file)
icmp_request_packets = [packet for packet in packets if packet.haslayer(scapy.ICMP) and packet[scapy.ICMP].type == 8]
# Obtener el primer caracter del campo 'data' de cada paquete ICMP Request
characters = [chr(packet[scapy.ICMP].load[0]) for packet in icmp_request_packets]
# Función para descifrar el mensaje con cifrado César
def decrypt_cesar(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted_index = (ord(char) - ord('a') - shift) % 26
            decrypted_char = chr(shifted_index + ord('a'))
            decrypted_text += decrypted_char
        else:
            decrypted_text += char
    return decrypted_text
# Diccionario para almacenar las opciones de descifrado y su frecuencia
decrypted_options = {}
# Probar todas las combinaciones posibles de cifrado César
for shift in range(26):
    decrypted_message = decrypt_cesar(characters, shift)
    
    # Almacenar la opción de descifrado en el diccionario
    decrypted_options[shift] = decrypted_message
# Encontrar la opción más probable (con mayor frecuencia de letras comunes)
most_probable_shift = max(decrypted_options, key=lambda k: sum(decrypted_options[k].count(letter) for letter in "aeiou"))
# Imprimir todas las opciones de descifrado con la opción más probable resaltada en verde
for shift, message in decrypted_options.items():
    if shift == most_probable_shift:
        print(f"Shift {shift:2d}: {Fore.GREEN}{message.upper()}{Style.RESET_ALL}")
    else:
        print(f"Shift {shift:2d}: {message}")
