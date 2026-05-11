import sys

def extract_key(trace_file):
    print(f"[*] Analyzing execution trace: {trace_file}...")
    
    bits = []
    mul_count = 0
    in_loop = False
    
    with open(trace_file, 'r') as f:
        for line in f:
            # The 'bt' (Bit Test) instruction acts as our loop boundary
            if " bt " in line:
                if in_loop:
                    # If we counted more than 1 multiply, the conditional branch executed!
                    if mul_count > 1:
                        bits.append('1')
                    else:
                        bits.append('0')
                
                in_loop = True
                mul_count = 0 # Reset counter for the next loop iteration
                
            # Count every multiplication operation within the current loop boundary
            elif ("imul " in line or " mul " in line) and in_loop:
                mul_count += 1
                
    # Evaluate the very last loop iteration after the file ends
    if in_loop:
        if mul_count > 1:
            bits.append('1')
        else:
            bits.append('0')
            
    # The algorithm works from MSB to LSB. Isolate the final 64 bits.
    if len(bits) > 64:
        bits = bits[-64:]
        
    binary_string = "".join(bits)
    
    try:
        decimal_key = int(binary_string, 2)
    except ValueError:
        print("[-] Error: Could not extract a valid binary sequence.")
        sys.exit(1)
    
    print(f"[*] Loop iterations analyzed: {len(bits)}")
    print(f"[*] Extracted Binary Key  : {binary_string}")
    print(f"[*] Extracted Decimal Key : {decimal_key}")
    
    with open("key.txt", "w") as kf:
        kf.write(str(decimal_key))
    print("[+] Successfully wrote the extracted key to key.txt")

if __name__ == "__main__":
    extract_key("trace.txt")
