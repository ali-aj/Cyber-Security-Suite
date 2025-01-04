import itertools
import string
import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def get_charset(charset_type):
    charsets = {
        'lower': string.ascii_lowercase,
        'upper': string.ascii_uppercase,
        'digits': string.ascii_letters + string.digits,
        'special': string.ascii_letters + string.digits + string.punctuation
    }
    return charsets.get(charset_type, charsets['lower'])

def estimate_complexity(target, charset):
    charset_length = len(charset)
    password_length = len(target)
    return charset_length ** password_length

def check_password_chunk(args):
    start_length, end_length, charset, target = args
    attempts = 0
    for length in range(start_length, end_length + 1):
        for guess in itertools.product(charset, repeat=length):
            password = ''.join(guess)
            attempts += 1
            if password == target:
                return {'found': True, 'password': password, 'attempts': attempts}
    return {'found': False, 'attempts': attempts}

def simulate(target, charset_type='lower', max_attempts=None, num_threads=4):
    try:
        charset = get_charset(charset_type)
        start_time = time.time()
        estimated_combinations = estimate_complexity(target, charset)
        total_attempts = 0
        
        # Split work into chunks
        chunks = [(i, i+1, charset, target) for i in range(1, len(target) + 1)]
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(check_password_chunk, chunk) for chunk in chunks]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    total_attempts += result['attempts']
                    
                    if result['found']:
                        yield {
                            "status": "Success",
                            "message": f"Password found: {result['password']}",
                            "attempts": total_attempts,
                            "time": time.time() - start_time,
                            "progress": 100
                        }
                        return
                        
                    if max_attempts and total_attempts >= max_attempts:
                        yield {
                            "status": "Failed",
                            "message": "Maximum attempts reached",
                            "attempts": total_attempts,
                            "time": time.time() - start_time,
                            "progress": (total_attempts / estimated_combinations) * 100
                        }
                        return
                        
                    if total_attempts % 1000 == 0:
                        yield {
                            "status": "Progress",
                            "attempts": total_attempts,
                            "time": time.time() - start_time,
                            "progress": min((total_attempts / estimated_combinations) * 100, 99.9)
                        }
                        
                except Exception as e:
                    logger.error(f"Error in worker thread: {str(e)}")
                    
        yield {
            "status": "Failed",
            "message": "Password not found",
            "attempts": total_attempts,
            "time": time.time() - start_time,
            "progress": 100
        }
                    
    except Exception as e:
        logger.error(f"Error in brute force simulation: {str(e)}")
        yield {
            "status": "Error",
            "message": str(e),
            "attempts": total_attempts,
            "time": time.time() - start_time,
            "progress": 0
        }