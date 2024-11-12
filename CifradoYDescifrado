from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Función para ajustar la clave según el algoritmo
def adjust_key(key, algorithm):
    if algorithm == 'DES':
        required_length = 8
    elif algorithm == '3DES':
        required_length = 24
    elif algorithm == 'AES':
        required_length = 32  # AES-256 requiere una clave de 32 bytes
    else:
        raise ValueError("Algoritmo no soportado.")
        
    # Completa o trunca la clave
    if len(key) < required_length:
        key += get_random_bytes(required_length - len(key))
    elif len(key) > required_length:
        key = key[:required_length]
    return key

# Función para ajustar el IV según el algoritmo
def adjust_iv(iv, algorithm):
    if algorithm == 'AES':
        required_length = 16
    else:
        required_length = 8
    
    # Completa o trunca el IV
    if len(iv) < required_length:
        iv += get_random_bytes(required_length - len(iv))
    elif len(iv) > required_length:
        iv = iv[:required_length]
    return iv

# Función de cifrado y descifrado
def encrypt_decrypt(text, key, iv, algorithm):
    if algorithm == 'DES':
        cipher_encrypt = DES.new(key, DES.MODE_CBC, iv)
        cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)
    elif algorithm == '3DES':
        cipher_encrypt = DES3.new(key, DES3.MODE_CBC, iv)
        cipher_decrypt = DES3.new(key, DES3.MODE_CBC, iv)
    elif algorithm == 'AES':
        cipher_encrypt = AES.new(key, AES.MODE_CBC, iv)
        cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Algoritmo no soportado.")

    # Cifrado
    encrypted_text = cipher_encrypt.encrypt(pad(text.encode('utf-8'), cipher_encrypt.block_size))
    # Descifrado
    decrypted_text = unpad(cipher_decrypt.decrypt(encrypted_text), cipher_decrypt.block_size)
    
    return base64.b64encode(encrypted_text).decode('utf-8'), decrypted_text.decode('utf-8')
#Funcion Descifrado
def decrypt(text, key, iv, algorithm):
    if algorithm == 'DES':
        cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)
    elif algorithm == '3DES':
        cipher_decrypt = DES3.new(key, DES3.MODE_CBC, iv)
    elif algorithm == 'AES':
        cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Algoritmo no soportado.")
    # Descifrado
    decrypted_text = unpad(cipher_decrypt.decrypt(encrypted_text), cipher_decrypt.block_size)
    
    return decrypted_text.decode('utf-8')
# Solicitar datos de entrada desde la terminal
def main():
    text = input("Ingrese el texto a cifrar: ")
    key = input("Ingrese la clave en formato ASCII: ").encode('utf-8')
    iv = input("Ingrese el IV en formato ASCII (debe ser de 8 bytes para DES y 3DES, y de 16 bytes para AES): ").encode('utf-8')
    algorithm = input("Elija el algoritmo (DES, 3DES, AES): ")

    # Ajustar la clave y el IV al tamaño adecuado
    key = adjust_key(key, algorithm)
    iv = adjust_iv(iv, algorithm)
    print(f"Clave ajustada: {key}")
    print(f"IV ajustado: {iv}")

    # Ejecutar cifrado y descifrado
    encrypted_text, decrypted_text = encrypt_decrypt(text, key, iv, algorithm)
    print(f"Texto cifrado (base64): {encrypted_text}")
    print(f"Texto descifrado: {decrypted_text}")

if __name__ == "__main__":
    main()
