import math
import random

def is_prime(n):
    """Check if a number is prime"""
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def mod_inverse(a, m):
    """Calculate modular multiplicative inverse"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, x, _ = extended_gcd(a, m)
    return (x % m + m) % m

def find_primitive_roots(p):
    """Find primitive roots modulo p"""
    if not is_prime(p):
        return []
    
    def factorize(n):
        factors = set()
        # Find prime factors of n
        for i in range(2, int(math.sqrt(n)) + 1):
            while n % i == 0:
                factors.add(i)
                n //= i
        if n > 1:
            factors.add(n)
        return factors

    # Find prime factors of p-1
    phi = p - 1
    factors = factorize(phi)
    
    primitive_roots = []
    # Check numbers from 2 to p-1
    for g in range(2, p):
        is_primitive = True
        for factor in factors:
            if pow(g, phi // factor, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            primitive_roots.append(g)
            
    return primitive_roots

def validate_elgamal_params(prime, root, private_key):
    if not is_prime(prime):
        return {"valid": False, "error": "The number is not prime"}
    
    primitive_roots = find_primitive_roots(prime)
    if root not in primitive_roots:
        return {"valid": False, "error": f"Not a primitive root. Valid roots are: {primitive_roots[:5]}..."}
    
    if private_key >= prime or private_key < 1:
        return {"valid": False, "error": "Invalid private key. Must be between 1 and p-1"}
    
    return {"valid": True}

def generate_keys(prime, root, private_key):
    """Generate public key"""
    if not validate_elgamal_params(prime, root, private_key)["valid"]:
        raise ValueError("Invalid parameters")
    
    public_key = pow(root, private_key, prime)
    return public_key

def encrypt(message, prime, root, public_key):
    """Encrypt a message (number or text)"""
    k = random.randint(1, prime-2)  # Random ephemeral key
    c1 = pow(root, k, prime)
    s = pow(public_key, k, prime)
    
    try:
        # Try to handle message as number
        m = int(message)
        if m >= prime:
            raise ValueError(f"Message value {m} must be smaller than prime {prime}")
        c2 = [(m * s) % prime]
    except ValueError:
        # Handle as text if not a valid number
        c2 = []
        for char in message:
            m = ord(char)
            if m >= prime:
                raise ValueError(f"Message character value {m} is too large for prime {prime}")
            c2.append((m * s) % prime)
    
    return c1, c2

def decrypt(c1, c2_list, prime, private_key):
    """Decrypt a message"""
    s = pow(c1, private_key, prime)
    s_inv = mod_inverse(s, prime)
    
    return str((c2_list * s_inv) % prime)
