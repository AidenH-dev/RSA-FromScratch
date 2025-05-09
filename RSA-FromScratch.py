# Aiden Habboub May 8th 2025 

# Project: RSA Encryption & Decryption Fully Implemented In Python With No External Libraries (Wthout Real-world padding (OAEP))

# STEP 1
#   Transform the characters to numbers in order to apply the cypher transformation: c=m^e%n 
#   Essentially were getting whatever characters are inputted to be a number we can use it as m 

# This section converts any input into a UTF 8 to act as the base to be encrypted.
# The function ord(char) returns the Unicode code point (number assigned to the character in the UTF8 Chart)
# [UTF8 Then turns that Unicode into Binary]
#
# It's not critical for the exercise but since it functions differently since it goes past 8 bits so it uses a 
# starting signifier if a characters' unicode is larger than a byte so a two byte character would look like 110xxxxx 10xxxxxx
# where the "110" signifies how many bytes the character is going to take up. 
# (Might be helpful to know if I write the encryptiong process in lower dimention code for optimization)

INPUT = ":)"
# UTF ENCODING INTO UNICODE
def encode_to_utf8_unicode(input_text):
    encoded_unicode_array = []
    #print("UTF-8 Unicode: ")
    for char in input_text:
        code = ord(char)
        encoded_unicode_array.append(code)
        #print(f"{char} -> {code}")
    #print("-> Encoded Unicode Set: ", encoded_unicode_array, "\n")
    return encoded_unicode_array

# UTF DECODING FROM UNICODE
def decode_from_utf8_unicode(encoded_unicode_array):
    unencoded_unicode_array = []
    #print("UTF-8 Characters: ")
    for encoded_char in encoded_unicode_array:
        char = chr(encoded_char)
        unencoded_unicode_array.append(char)
        #print("Unencoded Unicode: ", char)
    #print("-> Unencoded UTF-8 Set: ", unencoded_unicode_array, "\n")
    return unencoded_unicode_array


# STEP 2
#   Securely generate the prime numbers that will be used in Euler's totient function 
#
# This section uses the secrets library to generate two cryptographically secure prime numbers to use in Euler's totient function
# Broken up into three functions: is_prime, generate_prime, and generate_two_distinct_primes.

bits = 1024 # Standard for RSA 2048-bit encryption

import secrets 

# is_prime() uses the Miller-Rabin primality test over multiple itteration to conclude a number is highly likely to be prime
# it depends on modular arithmatic to determine if a number is acting like a prime number 
# n: the prime needed to be checked 
# k: defines the amount the Miller-Rabin itterates 
#    for example k=10 itterations has a 0.000095% chance of being incorrectly classified as prime or 1 in 1,048,576
def is_prime(n, k=10):
    """Miller-Rabin primality test with k iterations (higher k = more accurate)."""
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0: # this is likly going to be rundundant in this context since this function will likely
                   # only ever used in the generate_prime function where "num |= 1" already ensures odd numbers
        return False

    # write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # random int in [2, n-2]
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # composite
    return True  # probably prime

# Comes up with a random number and passes it to is_prime() to check if its prime
def generate_prime(bits):
    """Generates a random prime number of approximately bits bits."""
    while True:
        num = secrets.randbits(bits)
        num |= 1  # ensure it's odd
        num |= (1 << (bits - 1))  # ensure it has the correct bit length
        if is_prime(num):
            return num

# Keeps prompting generate_prime() until it generates two prime numbers that dont match 
def generate_two_distinct_primes(bits):
    """Generates two distinct random prime numbers of bits bits."""
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)
    return p, q

# TEST MARK: print(generate_two_distinct_primes(bits))


# STEP 3
#   Generate Keys
#
#   Take the two Prime Numbers and apply them the Euler's Totient Function and generate the private & public key
#   Imports math library to calculate the greatest common denominator when generating the public key

import math

# calculate_n() takes the randomly generated prime numbers generate_two_distinct_primes() 
# makes and uses it to calculate the modulus n needed to create the public and private keys 
# n is also used in the modulus operations when encoding and decoding
def calculate_n(p ,q):
    n = p * q 
    return n


def calculate_eulers_totient(p, q):
    φ_n = (p-1) * (q-1)
    return φ_n

def create_public_exponent(φ_n):
    if math.gcd(65537, φ_n) == 1:
        return 65537
    else: 
        while True:
            e = secrets.randbits((bits * 2) - 2)
            if e < φ_n and e > 1 and math.gcd(e, φ_n)==1: 
                return e

# Implements the Extended Euclidean Algorithm to find the private exponent "d"
def create_private_exponent(e, φ_n):
    r0 = φ_n
    r1 = e
    t0 = 0
    t1 = 1

    while True:
        q = r0 // r1
        r2 = r0 - q * r1
        t2 = t0 - q * t1

        r0 = r1
        r1 = r2
        t0 = t1 
        t1 = t2

        if r1 == 0:
            d = t0%φ_n

            if (e * d) % φ_n == 1:
                return d
            else: 
                print("Oh no...")

def create_keys():
    p, q = generate_two_distinct_primes(bits)

    n = calculate_n(p, q)
    φ_n = calculate_eulers_totient(p, q)

    e = create_public_exponent(φ_n)

    d = create_private_exponent(e, φ_n)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key
    
# TEST MARK: print(create_keys())

# STEP 4 
#   Encrypt the message
#
#   Use the public key encrypt a message by taking the message in number form 
#   and using the public exponent e and modulus n to calculate the cryptographic message

public_key, private_key = create_keys()

def encrypt_message(message):
    encrypted_message_array = []

    encoded_unicode_array = encode_to_utf8_unicode(message)

    e, n = public_key

    for i in encoded_unicode_array:
        encrypted_message_array.append(pow(i, e, n))

    return encrypted_message_array

# TEST MARK: print(encrypt_message(INPUT))

# Step 5
#   Decrypt the message using the private key
#

def decrypt_message(encrypted_message_array):
    encoded_unicode_array = []

    d, n = private_key

    # Perform RSA decryption: m = c^d mod n
    for i in encrypted_message_array:
        encoded_unicode_array.append(pow(i, d, n))

    # Convert Unicode values to characters and join into a string
    decrypted_string = ''.join(chr(code_point) for code_point in encoded_unicode_array)

    return decrypted_string


def main():
    print("=== RSA Encryption/Decryption ===")
    
    # Prompt user for input
    user_input = input("Enter a message to encrypt: ")

    # Encrypt
    secret_message = encrypt_message(user_input)
    print("\nEncrypted Message:")
    print(secret_message)

    # Decrypt
    not_so_secret_message = decrypt_message(secret_message)
    print("\nDecrypted Message:")
    print(not_so_secret_message)

if __name__ == "__main__":
    main()
