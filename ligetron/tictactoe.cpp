/*
 * Tic-Tac-Toe Validity Proof for Ligero - Modified Version
 * 
 * Arguments:
 *   argv[1] - moves as position string (public) - format: "1,4,3,6,2,0,8,7,5"
 *   argv[2] - seed (private)
 *   argv[3] - user_public_key (public)
 *   argv[4] - expected_hash (public) - 64 hex characters
 */

 #include <ligetron/api.h>
 #include <cstring>
 
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
 
 // Parse moves string into position array
 bool parse_positions(const char* moves_str, int positions[], int* num_moves) {
     *num_moves = 0;
     const char* ptr = moves_str;
     
     while (*ptr && *num_moves < 9) {
         // Parse position (0-8)
         int pos = *ptr - '0';
         if (pos < 0 || pos > 8) return false;
         
         positions[*num_moves] = pos;
         (*num_moves)++;
         
         ptr++; // move to next char
         if (*ptr == ',') ptr++; // skip comma
     }
     
     return true;
 }
 
 // Validate tic-tac-toe game logic with positions 0-8
 bool validate_tictactoe_positions(int positions[], int num_moves) {
     int board[9] = {0}; // 0=empty, 1=player1, 2=player2
     
     // Play the moves
     for (int i = 0; i < num_moves; i++) {
         int pos = positions[i];
         int player = (i % 2 == 0) ? 1 : 2; // player1=1, player2=2
         
         // Validate position and check if empty
         if (pos < 0 || pos > 8) return false;
         if (board[pos] != 0) return false; // Position occupied
         
         board[pos] = player;
     }
     
     // Basic validation: moves should be valid (positions unique and in range)
     // The circuit now only validates that the moves are structurally valid
     // without checking for a specific winner
     return true;
 }
 
 // Construct game data string 
 void construct_game_data(char* output, const char* moves_str, const char* public_key, const char* seed) {
     // Format: moves|public_key|seed
     strcpy(output, moves_str);
     strcat(output, "|");
     strcat(output, public_key);
     strcat(output, "|");
     strcat(output, seed);
 }
 
 int main(int argc, char* argv[]) {
     // Get argument lengths (like working example)
     int args_len[argc];
     args_len_get(argv, args_len);
     
     // Get inputs in new order
     const char* moves_str = argv[1];        // public
     const char* seed = argv[2];             // private
     const char* public_key = argv[3];       // public
     const char* expected_hash_hex = argv[4]; // public
     
     // Mark public inputs as constants
     for (int i = 0; i < args_len[1]; i++) {
         assert_constant(moves_str[i]);
     }
     
     for (int i = 0; i < args_len[3]; i++) {
         assert_constant(public_key[i]);
     }
     
     for (int i = 0; i < 64; i++) {
         assert_constant(expected_hash_hex[i]);
     }
     
     // Parse positions
     int positions[9];
     int num_moves;
     bool moves_valid = parse_positions(moves_str, positions, &num_moves);
     assert_one(moves_valid);
     
     // Validate game logic (basic structural validation)
     bool game_valid = validate_tictactoe_positions(positions, num_moves);
     assert_one(game_valid);
     
     // Construct game data for hashing
     char game_data[1000];
     construct_game_data(game_data, moves_str, public_key, seed);
     
     // Get actual length
     unsigned int game_data_len = strlen(game_data);
     
     // Compute SHA256 hash using working implementation
     unsigned char computed_hash[32];
     mysha256(computed_hash, (const unsigned char*)game_data, game_data_len);
     
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
     
     // Compare hex strings character by character
     for (int i = 0; i < 64; i++) {
         assert_one(computed_hash_hex[i] == expected_hash_hex[i]);
     }
     
     return 0;
 }