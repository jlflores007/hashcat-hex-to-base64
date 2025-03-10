# **Hashcat to Base64 Converter**
 
This Python script converts a SHA256 hash and salt into a Base64-encoded format compatible with Hashcat. It was designed for the Hack The Box lab "Titanic," which uses Gitea.

## Arguments

| Argument | Description |
| -------- | ----------- |
| -H or --hash | Hex-encoded hash string |
| -s or --salt | Salt value |
| -i or --iteration | Number of iterations |
| -a or --algorithm | Hashing algorithm (e.g., sha256 |

## Example Output
sha256:iterations:salt:hash

## **Usage**
Run the script with the following command:

```sh
python3 convertHash.py -H "<Hex_hash>" -s "<salt>" -i "<iterations>" -a "<algorithm>"
