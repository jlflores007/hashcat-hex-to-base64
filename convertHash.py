#!/usr/bin/python3
#
# Goal: use Hashcat to brute-force a password with the salt to have it ready for hashcat
# Code by: Jlflores007
#
# Step 1: Store the hash and salt thats from the command-line.
# Step 2: Checking that hash is on the argument -h for hash and -s for salt.
# Step 3: Convert the hash and salt from HEX-encoded to bytes then Base64  
# Step 4: Output Goal: sha256:iterations:salt:hash


import base64, argparse

def convertByte(hashString, saltString):
    # Checks if its a valid HEX and converts it into a byte.
    try:
        hashByte = bytes.fromhex(hashString)
        saltByte = bytes.fromhex(saltString)
        return hashByte, saltByte
    except ValueError as e:
        print(f"Not a valid Hex String: {e}")
        return None, None

def convertBase64(hashByte, saltByte):
    # Converts the byte string into Base64 for Hashcat
    try:
        hashBase = base64.b64encode(hashByte).decode('utf-8')
        saltBase = base64.b64encode(saltByte).decode('utf-8')
        return hashBase, saltBase
    except Exception as e:
        print(f"Error encoding to Base64: {e}")
        return None, None


def convertHash(hashString, saltString, iteration, algorithm):
    # Converts the Original Hex string to Byte
    byteHash, byteSalt = convertByte(hashString, saltString)

    if byteHash is None or byteSalt is None:
        return

    # Converts the Byte to the Base64 for Hashcat
    baseHash, baseSalt = convertBase64(byteHash, byteSalt)

    if baseHash is None or baseSalt is None:
        return

    # Outputs the final to use for 
    print(f"{algorithm}:{iteration}:{baseSalt}:{baseHash}")

def main():
    # Create the parse with description and example
    parser = argparse.ArgumentParser(description="Converting SHA256 into a format compatible with Hashcat",
                                     epilog="Example:\n  python3 convertHash.py -H 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' -s 'somesalt' -i 50000 -a 'sha256'\n")

    # Add arguments
    parser.add_argument("-hash","-H", help="Hash", required=True)
    parser.add_argument("-salt","-s", help="Salt", required=True)
    parser.add_argument("-iteration","-i", help="Iteration", required=True)
    parser.add_argument("-algorithm","-a", help="Type of Algorithm", required=True)

    # Parse the arguments
    args = parser.parse_args()

    # Call the function with the parsed arguments
    convertHash(args.hash, args.salt, int(args.iteration), args.algorithm.lower().strip())

if __name__ == "__main__":
    main()

