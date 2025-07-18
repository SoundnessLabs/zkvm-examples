/*
 * 8-Queens Validity Proof for Ligero - Working Version with Hash Verification
 * 
 * Arguments:
 *   argv[1] - queens_input (private) - format: "01234567" (8 pairs of row,col digits)
 *   argv[2] - random_seed (private)
 *   argv[3] - public_key (private)
 *   argv[4] - expected_hash (public) - 64 hex characters
 */

#include <ligetron/api.h>
#include <cstring>

/* Working SHA256 implementation from the tic-tac-toe example */
#define S(x, n) (((((int)(x)&0xFFFFFFFFU)>>(int)((n)&31))|((int)(x)<<(int)((32-((n)&31))&31)))&0xFFFFFFFFU)
#define R(x, n) (((x)&0xFFFFFFFFU)>>(n))
#define Gamma0(x) (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x) (S(x, 17) ^ S(x, 19) ^ R(x, 10))
#define RND(a,b,c,d,e,f,g,h,i) \
    t0 = h + (S(e, 6) ^ S(e, 11) ^ S(e, 25)) + (g ^ (e & (f ^ g))) + K[i] + W[i]; \
    t1 = (S(a, 2) ^ S(a, 13) ^ S(a, 22)) + (((a | b) & c) | (a & b)); \
    d += t0; \
    h  = t0 + t1;
#define STORE32H(x, y) \
    (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255); \
    (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255);
#define LOAD32H(x, y) \
    x = ((int)((y)[0]&255)<<24)|((int)((y)[1]&255)<<16)|((int)((y)[2]&255)<<8)|((int)((y)[3]&255));
#define SHA256_COMPRESS(buff) \
    for (i = 0; i < 8; i++) S[i] = sha256_state[i]; \
    for (i = 0; i < 16; i++) LOAD32H(W[i], buff + (4*i)); \
    for (i = 16; i < 64; i++) W[i] = Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16]; \
    for (i = 0; i < 64; i++) { \
        RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i); \
        t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; \
        S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t; \
    } \
    for (i = 0; i < 8; i++) sha256_state[i] = sha256_state[i] + S[i];

constexpr unsigned int K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

int mysha256 (unsigned char *out, const unsigned char* in, int len) {
    int i;
    int sha256_length = 0;

    int sha256_state[8];
    sha256_state[0] = 0x6A09E667;
    sha256_state[1] = 0xBB67AE85;
    sha256_state[2] = 0x3C6EF372;
    sha256_state[3] = 0xA54FF53A;
    sha256_state[4] = 0x510E527F;
    sha256_state[5] = 0x9B05688C;
    sha256_state[6] = 0x1F83D9AB;
    sha256_state[7] = 0x5BE0CD19;

    int S[8], W[64];
    int t0, t1, t;
    unsigned char sha256_buf[64];

    while (len >= 64) {
       SHA256_COMPRESS(in);
       sha256_length += 64 * 8;
       in += 64;
       len -= 64;
    }
    for (int i = 0; i < len; i++) {
        sha256_buf[i] = in[i];
    }
    sha256_length += len * 8;
    sha256_buf[len++] = 0x80;
    if (len > 60) {
        while (len < 64) sha256_buf[len++] = 0;
        SHA256_COMPRESS(sha256_buf);
        len = 0;
    }
    while (len < 60) sha256_buf[len++] = 0;

    STORE32H(sha256_length, sha256_buf + 60);
    SHA256_COMPRESS(sha256_buf);

    for (i = 0; i < 8; i++) {
        STORE32H(sha256_state[i], out + 4*i);
    }

    return 0;
}

// Construct queens data string 
void construct_queens_data(char* output, const char* queens_input, const char* random_seed, const char* public_key) {
    // Format: queens_input|random_seed|public_key
    strcpy(output, queens_input);
    strcat(output, "|");
    strcat(output, random_seed);
    strcat(output, "|");
    strcat(output, public_key);
}

int main(int argc, char** argv) {
    // Get argument lengths
    int args_len[argc];
    args_len_get(argv, args_len);
    
    // Get inputs
    const char* queens_input = argv[1];
    const char* random_seed = argv[2];
    const char* public_key = argv[3];
    const char* expected_hash_hex = argv[4];  // Expected hash as hex string
    
    // Validate input length
    assert_one(strlen(queens_input) == 16); // Ensure input length is 16

    int rows[8], cols[8];

    // Parse the 8 queen positions from input
    for (int i = 0; i < 8; i++) {
        rows[i] = queens_input[2 * i] - '0';
        cols[i] = queens_input[2 * i + 1] - '0';
        assert_one(rows[i] >= 0 && rows[i] < 8);
        assert_one(cols[i] >= 0 && cols[i] < 8);
    }

    // Check all pairs of queens for conflicts
    for (int i = 0; i < 8; i++) {
        for (int j = i + 1; j < 8; j++) {
            bool same_row = (rows[i] == rows[j]);
            bool same_col = (cols[i] == cols[j]);
            bool same_diag_first = (rows[i] - rows[j]) == (cols[i] - cols[j]);
            bool same_diag_second = (rows[j] - rows[i]) == (cols[i] - cols[j]);
            assert_one(!(same_row || same_col || same_diag_first || same_diag_second));
        }
    }
    
    // Construct queens data for hashing
    char queens_data[1000];
    construct_queens_data(queens_data, queens_input, random_seed, public_key);
    
    // Get actual length
    unsigned int queens_data_len = strlen(queens_data);
    
    // Compute SHA256 hash using working implementation
    unsigned char computed_hash[32];
    mysha256(computed_hash, (const unsigned char*)queens_data, queens_data_len);
    
    // Convert computed hash to hex string for comparison
    char computed_hash_hex[65];
    for (int i = 0; i < 32; i++) {
        unsigned char byte = computed_hash[i];
        int high = (byte >> 4) & 0x0F;
        int low = byte & 0x0F;
        computed_hash_hex[i*2] = (high < 10) ? ('0' + high) : ('a' + high - 10);
        computed_hash_hex[i*2+1] = (low < 10) ? ('0' + low) : ('a' + low - 10);
    }
    computed_hash_hex[64] = '\0';
    
    // Mark expected hash hex string as public
    for (int i = 0; i < 64; i++) {
        assert_constant(expected_hash_hex[i]);
    }
    
    // Compare hex strings character by character
    for (int i = 0; i < 64; i++) {
        assert_one(computed_hash_hex[i] == expected_hash_hex[i]);
    }

    return 0;
}