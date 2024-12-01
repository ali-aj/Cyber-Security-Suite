import itertools
import string

def simulate(target):
    chars = string.ascii_lowercase + string.digits
    max_length = 4  # Limit for demonstration purposes

    for length in range(1, max_length + 1):
        for guess in itertools.product(chars, repeat=length):
            password = ''.join(guess)
            if password == target:
                return {
                    "status": "Success",
                    "message": f"Password cracked: {password}"
                }
    
    return {
        "status": "Failed",
        "message": "Password not found within constraints"
    }

