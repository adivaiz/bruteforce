import hashlib
import itertools
import time
import tracemalloc
from typing import Tuple


def generate_passwords(charset: str, max_length: int):
    if charset == "":
        raise ValueError("Character set cannot be empty")
    elif max_length < 1:
        raise ValueError("Max length must be at least 1")

    for i in range(1, max_length + 1):  # the length of possible passwords to create in from 1 to max_length include
        for combination in itertools.product(charset,
                                             repeat=i):  # create tuple that contains all the passwords in length i
            yield ''.join(combination)


def hash_password(password: str, algorithm: str, salt: str) -> str:
    allowed = ['sha256', 'sha1', 'md5', 'sha512', 'sha3_256']
    if salt is None or not isinstance(salt, str):
        raise ValueError("Salt must be a non-empty string")
    elif algorithm not in allowed:
        raise ValueError("Unsupported hash algorithm")
    newstri = salt + password
    encodedpassword = newstri.encode()  # convert to byte
    hashalgo = hashlib.new(algorithm)  # find the hash algorithm in hashlib
    hashalgo.update(encodedpassword)  # make hash with the function we choose and the byte of string
    newpassword = hashalgo.hexdigest()  # convert to hex
    return newpassword


def calculate_total_combinations(charset: str, max_length: int) -> int:
    total = 0
    charsetlen = len(charset)
    for i in range(1, max_length + 1):  # multiply each length of the word in number of optional characters
        total += charsetlen ** i
    return total


def brute_force_password(charset: str, max_length: int, target_hash: str, algorithm: str, salt: str) -> Tuple[str, int]:
    counter = 0
    for password in generate_passwords(charset, max_length):
        counter += 1
        passw = hash_password(password, algorithm, salt)
        if passw == target_hash:
            return (password, counter)
    return ("", counter)


def measure_performance_start() -> float:  # start timer and trace to memory
   startime = time.time()
   tracemalloc.start()
   return startime


def measure_performance_end(start_time: float) -> Tuple[float, float, float]:
    endtime = time.time()  # close the clock
    totaltime = endtime - start_time  # calculate total time
    currentmemory, peakmemory = tracemalloc.get_traced_memory()
    currentmemory_mb = round(currentmemory / (1024 ** 2), 6)  # Convert bytes to megabytes
    peakmemory_mb = round(peakmemory / (1024 ** 2), 6)  # Convert bytes to megabytes
    tracemalloc.stop()
    return (totaltime, currentmemory_mb, peakmemory_mb) # tuple


def get_charset(option: str, custom_charset: str = '') -> str:
    options = ['lowercase', 'uppercase', 'digits', 'mixed', 'custom']  # list of options
    if custom_charset is None:
        raise ValueError("Custom charset must be provided when opinion is 'custom'")
    elif option not in options:
        raise ValueError("invalid charset option.Choose from 'lowercase','uppercase','digits','mixed','customer'.")
    match option:  # switch cases for the chosen option
        case 'lowercase':
            return "abcdefghijklmnopqrstuvwxyz"
        case 'uppercase':
            return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        case 'digits':
            return "0123456789"
        case 'mixed':
            return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        case 'custom':
            return custom_charset


def brute_force(target_hash: str, charset: str, max_length: int, algorithm: str, salt: str) -> Tuple[str, int, float, float, float, int]:
    total_combinations = calculate_total_combinations(charset, max_length)  # use this function to calculate total comb
    starttime = measure_performance_start()  # turn on the timer and the memory trace
    tup = brute_force_password(charset, max_length, target_hash, algorithm, salt)
    tup2 = measure_performance_end(starttime)
    theend = (tup[0], tup[1], tup2[0], tup2[1], tup2[2], total_combinations)
    # tup[0]: הסיסמה שנמצאה (אם ישנה).
    # tup[1]: מספר הניסיונות שנעשו.
    # tup2[0]: הזמן הכולל שחלף.
    # tup2[1]: השימוש הנוכחי בזיכרון.
    # tup2[2]: שיא השימוש בזיכרון.
    return theend


# Example usage and test cases:
if __name__ == "__main__":
    charset_option = 'lowercase'  # Options: 'lowercase', 'uppercase', 'digits', 'mixed', 'custom'
    custom_charset = ''  # Define your custom charset here if option is 'custom'
    charset = get_charset(charset_option, custom_charset)
    print(f"Selected charset: {charset}")
    max_length = 4  # Limiting to length of 4 for demo purposes
    target_password = "abcd"
    algorithm = "sha256"
    salt = ""
    target_hash = hash_password(target_password, algorithm, salt)
    print(f"Testing with target password: {target_password}, algorithm: {algorithm}, salt: {salt}")
    print(f"Target password hash: {target_hash}")

    cracked_password, attempts, time_taken, current_memory, peak_memory, total_combinations = brute_force(target_hash,
                                                                                                          charset,
                                                                                                          max_length,
                                                                                                          algorithm,
                                                                                                          salt)

    if cracked_password:
        print(
            f"Password found: {cracked_password} in {attempts} attempts out of {total_combinations} possible combinations")
    else:
        print(f"Password not found after {attempts} attempts out of {total_combinations} possible combinations")

    print(f"Time taken: {time_taken:.2f} seconds")
    print(f"Current memory usage: {current_memory:.6f} MB")
    print(f"Peak memory usage: {peak_memory:.6f} MB")
