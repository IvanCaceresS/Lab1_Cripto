import sys

def cesar_cipher(text, shift):
    encrypted_text = ""

    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            encrypted_text += encrypted_char
        else:
            encrypted_text += char

    return encrypted_text

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py <texto> <corrimiento>")
        sys.exit(1)

    text_to_encrypt = sys.argv[1]
    shift = int(sys.argv[2])

    encrypted_text = cesar_cipher(text_to_encrypt, shift)
    print("Texto cifrado:", encrypted_text)
