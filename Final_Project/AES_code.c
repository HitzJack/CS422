#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <stdint.h>

#define AES_MAXNR 14
#define BLOCK_SIZE 16

/* ====================================================================
   CONTROL PANEL:
   0 = Custom Only (for performance profiling)
   1 = OpenSSL Only (for baseline)
   2 = Verification Mode (run both and compare — use this first!)
   ==================================================================== */
#define RUN_MODE 0

/* ========= Mirrors OpenSSL's AES_KEY internals ========= */
typedef struct {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
} AES_KEY_Custom;

/* ========= Round-key byte extraction (OpenSSL stores words little-endian-ish) ========= */
#define RK_BYTE0(rk) ((rk      ) & 0xFF)
#define RK_BYTE1(rk) ((rk >>  8) & 0xFF)
#define RK_BYTE2(rk) ((rk >> 16) & 0xFF)
#define RK_BYTE3(rk) ((rk >> 24) & 0xFF)

/* ===================================================================
   32-BIT SWAR HELPERS  (MixColumns)
   =================================================================== */

static inline uint32_t xtime32(uint32_t x) {
    uint32_t msb = x & 0x80808080u;
    return ((x & 0x7F7F7F7Fu) << 1) ^ ((msb >> 7) * 0x1Bu);
}

/* ===================================================================
   64-BIT SWAR ENGINE  (SubBytes — 8 GF(2^8) elements in parallel)
   =================================================================== */

static inline uint64_t xtime64(uint64_t x) {
    uint64_t msb = x & 0x8080808080808080ULL;
    return ((x & 0x7F7F7F7F7F7F7F7FULL) << 1) ^ ((msb >> 7) * 0x1BULL);
}

/* --- GF(2^8) multiplication: 8 bytes at once, fully unrolled --- */
static inline uint64_t gf_mul64(uint64_t a, uint64_t b) {
    const uint64_t M = 0x0101010101010101ULL;   /* LSB mask per byte  */
    const uint64_t N = 0x7F7F7F7F7F7F7F7FULL;   /* clear top bit/byte */
    uint64_t p = 0, lsb;

    lsb = b & M; p ^= a & (lsb * 255ULL); a = xtime64(a); b = (b >> 1) & N;
    lsb = b & M; p ^= a & (lsb * 255ULL); a = xtime64(a); b = (b >> 1) & N;
    lsb = b & M; p ^= a & (lsb * 255ULL); a = xtime64(a); b = (b >> 1) & N;
    lsb = b & M; p ^= a & (lsb * 255ULL); a = xtime64(a); b = (b >> 1) & N;
    lsb = b & M; p ^= a & (lsb * 255ULL); a = xtime64(a); b = (b >> 1) & N;
    lsb = b & M; p ^= a & (lsb * 255ULL); a = xtime64(a); b = (b >> 1) & N;
    lsb = b & M; p ^= a & (lsb * 255ULL); a = xtime64(a); b = (b >> 1) & N;
    lsb = b & M; p ^= a & (lsb * 255ULL);
    return p;
}

/* --- GF(2^8) squaring: 8 bytes at once via LINEAR MAP (much faster!) ---
 *
 * Squaring in GF(2^8) is a GF(2)-linear map: (Σ aᵢxⁱ)² = Σ aᵢx^(2i)
 * Reduce x^8,x^10,x^12,x^14 mod (x^8+x^4+x^3+x+1):
 *   x^8  ≡ x^4+x^3+x+1
 *   x^10 ≡ x^6+x^5+x^3+x^2
 *   x^12 ≡ x^7+x^5+x^3+x+1
 *   x^14 ≡ x^7+x^4+x^3+x
 *
 * Output bit ← input bits:
 *   out[0] = a0⊕a4⊕a6
 *   out[1] = a4⊕a6⊕a7
 *   out[2] = a1⊕a5
 *   out[3] = a4⊕a5⊕a6⊕a7
 *   out[4] = a2⊕a4⊕a7
 *   out[5] = a5⊕a6
 *   out[6] = a3⊕a5
 *   out[7] = a6⊕a7
 *
 * Verified: 0x53² = 0xB5  ✓   (and 0x80² = 0x9A = x^14 reduced ✓)
 */
static inline uint64_t gf_sq64(uint64_t x) {
    const uint64_t M = 0x0101010101010101ULL;

    uint64_t a0 =  x        & M;
    uint64_t a1 = (x >> 1)  & M;
    uint64_t a2 = (x >> 2)  & M;
    uint64_t a3 = (x >> 3)  & M;
    uint64_t a4 = (x >> 4)  & M;
    uint64_t a5 = (x >> 5)  & M;
    uint64_t a6 = (x >> 6)  & M;
    uint64_t a7 = (x >> 7)  & M;

    /* shared intermediates */
    uint64_t t46 = a4 ^ a6;
    uint64_t t47 = a4 ^ a7;
    uint64_t t56 = a5 ^ a6;   /* = out[5] */
    uint64_t t67 = a6 ^ a7;   /* = out[7] */

    uint64_t o0 = a0 ^ t46;       /* a0^a4^a6 */
    uint64_t o1 = t46 ^ a7;       /* a4^a6^a7 */
    uint64_t o2 = a1 ^ a5;
    uint64_t o3 = t47 ^ t56;      /* a4^a5^a6^a7 */
    uint64_t o4 = a2 ^ t47;       /* a2^a4^a7 */
    uint64_t o6 = a3 ^ a5;

    return o0 | (o1<<1) | (o2<<2) | (o3<<3) |
           (o4<<4) | (t56<<5) | (o6<<6) | (t67<<7);
}

/* --- GF(2^8) inverse via x^254  (Fermat: x^255=1 for x≠0, inv(0)=0) ---
 *
 * Optimal addition chain: 7 squarings + 4 multiplications
 * (original code used 11 multiplications — this saves ~35% on SubBytes)
 *
 *   x^2   = sq(x)
 *   x^3   = mul(x^2, x)
 *   x^6   = sq(x^3)
 *   x^12  = sq(x^6)
 *   x^14  = mul(x^12, x^2)
 *   x^15  = mul(x^14, x)
 *   x^30  = sq(x^15)
 *   x^60  = sq(x^30)
 *   x^120 = sq(x^60)
 *   x^240 = sq(x^120)
 *   x^254 = mul(x^240, x^14)
 */
static inline uint64_t gf_inv64(uint64_t x) {
    uint64_t x2   = gf_sq64(x);
    uint64_t x3   = gf_mul64(x2, x);
    uint64_t x6   = gf_sq64(x3);
    uint64_t x12  = gf_sq64(x6);
    uint64_t x14  = gf_mul64(x12, x2);
    uint64_t x15  = gf_mul64(x14, x);
    uint64_t x30  = gf_sq64(x15);
    uint64_t x60  = gf_sq64(x30);
    uint64_t x120 = gf_sq64(x60);
    uint64_t x240 = gf_sq64(x120);
    return gf_mul64(x240, x14);
}

/* --- Per-byte left circular rotation (SWAR) --- */
static inline uint64_t rotl8_64(uint64_t x, int n) {
    const uint64_t top = 0x0101010101010101ULL * ((0xFFULL << (8-n)) & 0xFFULL);
    return ((x & ~top) << n) | ((x & top) >> (8-n));
}

/* ===================================================================
   SubBytes on ALL 16 BYTES simultaneously, interleaved for ILP
   (Out-of-order CPUs can overlap the two independent inversion chains)
   =================================================================== */
static inline void subbytes_128(uint64_t *h1, uint64_t *h2) {
    uint64_t a = *h1, b = *h2;
    const uint64_t C = 0x6363636363636363ULL;

    /* Interleaved GF inverse — a-chain and b-chain are data-independent */
    uint64_t a2   = gf_sq64(a);      uint64_t b2   = gf_sq64(b);
    uint64_t a3   = gf_mul64(a2,a);  uint64_t b3   = gf_mul64(b2,b);
    uint64_t a6   = gf_sq64(a3);     uint64_t b6   = gf_sq64(b3);
    uint64_t a12  = gf_sq64(a6);     uint64_t b12  = gf_sq64(b6);
    uint64_t a14  = gf_mul64(a12,a2);uint64_t b14  = gf_mul64(b12,b2);
    uint64_t a15  = gf_mul64(a14,a); uint64_t b15  = gf_mul64(b14,b);
    uint64_t a30  = gf_sq64(a15);    uint64_t b30  = gf_sq64(b15);
    uint64_t a60  = gf_sq64(a30);    uint64_t b60  = gf_sq64(b30);
    uint64_t a120 = gf_sq64(a60);    uint64_t b120 = gf_sq64(b60);
    uint64_t a240 = gf_sq64(a120);   uint64_t b240 = gf_sq64(b120);
    uint64_t ai   = gf_mul64(a240,a14); uint64_t bi = gf_mul64(b240,b14);

    /* Affine transform: S(x) = inv(x) ⊕ rotl(1) ⊕ rotl(2) ⊕ rotl(3) ⊕ rotl(4) ⊕ 0x63 */
    *h1 = ai ^ rotl8_64(ai,1) ^ rotl8_64(ai,2) ^ rotl8_64(ai,3) ^ rotl8_64(ai,4) ^ C;
    *h2 = bi ^ rotl8_64(bi,1) ^ rotl8_64(bi,2) ^ rotl8_64(bi,3) ^ rotl8_64(bi,4) ^ C;
}

/* ===================================================================
   Pack two AES columns into one uint64_t for SubBytes processing.
   Layout: byte7=s[0][c1], byte6=s[1][c1], ..., byte0=s[3][c0]
   =================================================================== */
#define PACK_H(s,c0,c1) ( \
    ((uint64_t)(s)[0][c1]<<56)|((uint64_t)(s)[1][c1]<<48)| \
    ((uint64_t)(s)[2][c1]<<40)|((uint64_t)(s)[3][c1]<<32)| \
    ((uint64_t)(s)[0][c0]<<24)|((uint64_t)(s)[1][c0]<<16)| \
    ((uint64_t)(s)[2][c0]<< 8)| (uint64_t)(s)[3][c0])

#define UNPACK_H(h,s,c0,c1) do { \
    (s)[0][c0]=(h>>24)&0xFF; (s)[1][c0]=(h>>16)&0xFF; \
    (s)[2][c0]=(h>> 8)&0xFF; (s)[3][c0]= h     &0xFF; \
    (s)[0][c1]=(h>>56)&0xFF; (s)[1][c1]=(h>>48)&0xFF; \
    (s)[2][c1]=(h>>40)&0xFF; (s)[3][c1]=(h>>32)&0xFF; \
} while(0)

/* ===================================================================
   CORE AES-128 ENCRYPTION
   =================================================================== */
void AES_encrypt_custom(const unsigned char *in, unsigned char *out,
                        const AES_KEY_Custom *key)
{
    uint8_t s[4][4];   /* state[row][col] */
    uint32_t rk;
    uint8_t t;
    int i;

    /* === Load plaintext (column-major, per FIPS 197) === */
    for (i = 0; i < 4; i++) {
        s[0][i] = in[i*4+0]; s[1][i] = in[i*4+1];
        s[2][i] = in[i*4+2]; s[3][i] = in[i*4+3];
    }

    /* === Initial AddRoundKey (round 0) === */
    for (i = 0; i < 4; i++) {
        rk = key->rd_key[i];
        s[0][i] ^= RK_BYTE0(rk); s[1][i] ^= RK_BYTE1(rk);
        s[2][i] ^= RK_BYTE2(rk); s[3][i] ^= RK_BYTE3(rk);
    }

    /* === Rounds 1–9 === */
    for (int round = 1; round < 10; round++) {

        /* SubBytes: pack 16 bytes into 2 × uint64, apply S-box, unpack */
        uint64_t h1 = PACK_H(s,0,1);
        uint64_t h2 = PACK_H(s,2,3);
        subbytes_128(&h1, &h2);
        UNPACK_H(h1,s,0,1);
        UNPACK_H(h2,s,2,3);

        /* ShiftRows */
        t=s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=t;
        t=s[2][0]; s[2][0]=s[2][2]; s[2][2]=t;
        t=s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
        t=s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=t;

        /* MixColumns — 32-bit SWAR, verified against FIPS 197 test vector */
        for (i = 0; i < 4; i++) {
            uint32_t a0=s[0][i], a1=s[1][i], a2=s[2][i], a3=s[3][i];
            uint32_t c    = (a0<<24)|(a1<<16)|(a2<<8)|a3;
            uint32_t crot = (a1<<24)|(a2<<16)|(a3<<8)|a0;
            uint32_t res  = c ^ ((a0^a1^a2^a3)*0x01010101u) ^ xtime32(c^crot);
            s[0][i]=(res>>24)&0xFF; s[1][i]=(res>>16)&0xFF;
            s[2][i]=(res>> 8)&0xFF; s[3][i]= res     &0xFF;
        }

        /* AddRoundKey */
        for (i = 0; i < 4; i++) {
            rk = key->rd_key[round*4+i];
            s[0][i]^=RK_BYTE0(rk); s[1][i]^=RK_BYTE1(rk);
            s[2][i]^=RK_BYTE2(rk); s[3][i]^=RK_BYTE3(rk);
        }
    }

    /* === Final round (10) — no MixColumns === */
    {
        uint64_t h1 = PACK_H(s,0,1);
        uint64_t h2 = PACK_H(s,2,3);
        subbytes_128(&h1, &h2);
        UNPACK_H(h1,s,0,1);
        UNPACK_H(h2,s,2,3);
    }

    t=s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=t;
    t=s[2][0]; s[2][0]=s[2][2]; s[2][2]=t;
    t=s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
    t=s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=t;

    for (i = 0; i < 4; i++) {
        rk = key->rd_key[40+i];
        s[0][i]^=RK_BYTE0(rk); s[1][i]^=RK_BYTE1(rk);
        s[2][i]^=RK_BYTE2(rk); s[3][i]^=RK_BYTE3(rk);
    }

    /* === Store ciphertext === */
    for (i = 0; i < 4; i++) {
        out[i*4+0]=s[0][i]; out[i*4+1]=s[1][i];
        out[i*4+2]=s[2][i]; out[i*4+3]=s[3][i];
    }
}

/* ===================================================================
   PUBLIC ENTRY POINT  (called by analysis.c and check.py harness)
   =================================================================== */
void AES_code(unsigned char plaintext[16],
              unsigned char ciphertext[16],
              AES_KEY *enc_key)
{
#if RUN_MODE == 0
    AES_encrypt_custom(plaintext, ciphertext, (AES_KEY_Custom *)enc_key);

#elif RUN_MODE == 1
    AES_encrypt(plaintext, ciphertext, enc_key);

#elif RUN_MODE == 2
    unsigned char openssl_out[16];
    AES_encrypt(plaintext, openssl_out, enc_key);
    AES_encrypt_custom(plaintext, ciphertext, (AES_KEY_Custom *)enc_key);

    static int first_run = 1;
    if (first_run) {
        printf("\n=== MATCH VERIFICATION ===\n");
        printf("OpenSSL: "); for(int i=0;i<16;i++) printf("%02x",openssl_out[i]);
        printf("\nCustom : "); for(int i=0;i<16;i++) printf("%02x",ciphertext[i]);
        printf("\nRESULT : %s\n",
               memcmp(openssl_out, ciphertext, 16)==0 ?
               "SUCCESS! Perfect match." : "FAILED!  Outputs differ.");
        printf("==========================\n\n");
        first_run = 0;
    }
#endif
}