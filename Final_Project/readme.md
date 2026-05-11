# CS422 Assignment 3: Constant-Time AES-128 Implementation

**Group 6**
* Aman Dixit (230112)
* Aditya Gautam (220064)
* Abhijeet Agarwal (210025)
* Saaumitra Raaj (220928)

## About the Code
This repository contains a secure, constant-time software implementation of AES-128 encryption. To prevent cache-timing side-channel attacks, this implementation strictly avoids secret-dependent memory accesses by replacing traditional lookup tables (S-boxes) with dynamic mathematical calculations.

**Core Functions:**
* `AES_encrypt_custom`: The main encryption engine containing all the constant-time mathematical AES logic (SubBytes, MixColumns, etc.).
* `AES_code`: A smart wrapper function that acts as the public entry point. It routes the plaintext to either our custom code or the OpenSSL baseline depending on the selected configuration.

---

## ⚙️ The `RUN_MODE` Control Panel

To easily test, verify, and profile the code without having to comment out blocks of C code, we built a toggle switch using a macro at the top of `AES_code.c`. 

### Available Modes

- **Mode 0: Custom Only**  
  Runs only the custom constant-time AES implementation. Use this mode for performance profiling and benchmarking the secure implementation.

- **Mode 1: OpenSSL Only**  
  Runs only the standard OpenSSL AES implementation. Use this as a baseline for comparison.

- **Mode 2: Verification Mode**  
  Runs both implementations and compares their outputs. This is the recommended mode to start with to verify correctness. It will print a verification message on the first run showing whether the outputs match.

### How to Change Modes

1. Open `AES_code.c`
2. Find the `#define RUN_MODE 0` line (around line 12)
3. Change the number to the desired mode (0, 1, or 2)
4. Recompile and run the code