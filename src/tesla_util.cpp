#include "tesla.h"
#include "polyutil.h"

#include <sstream>

#define RANDOMNESS_SCALE 5
#define NONCE {1,2,3,4,5,6,7,8}

using namespace rlwe;
using namespace rlwe::tesla;

void tesla::Hash(unsigned char * output, const ZZX & p1, const ZZX & p2, const std::string & message, const KeyParameters & params) {
  // Round p1, p2 by applying [...]_{d,q}
  ZZX q1, q2;
  RightShiftCoeffs(q1, p1, params.GetLSBCount()); 
  RightShiftCoeffs(q2, p2, params.GetLSBCount()); 

  // Concatenate everything into a single string
  std::stringstream ss;
  ss << q1 << q2 << message;

  // Convert stream into actual string
  std::string cc = ss.str();

  // Convert input into its c_string equivalent
  const unsigned char * input = reinterpret_cast<const unsigned char *>(cc.c_str());
  long inlen = cc.length();

  // Perform hash function and store the result 
  crypto_hash_sha256(output, input, inlen);
}

void tesla::Encode(ZZX & dest, const unsigned char * hash_val, const KeyParameters & params) {
  long n = params.GetPolyModulusDegree();
  long w = params.GetEncodingWeight();

  // Get the number of bytes needed to represent `n` and `w`
  size_t n_bytes = sizeof(n);

  // We will need `w` random bits = `w / 8 + 1` random bytes to determine coefficient signs
  size_t w_bytes = w / 8 + 1;

  // The `r` buffer consists of two parts: the first `w_bytes` are used for signs, the rest is for rejection sampling
  const int rlen = w_bytes + params.GetEncodingWeight() * n_bytes * RANDOMNESS_SCALE;
  unsigned char r[rlen];

  // Fill `r` buffer with output from chacha20 stream cipher
  unsigned char nonce[crypto_stream_chacha20_NONCEBYTES] = NONCE;
  crypto_stream_chacha20(r, rlen, nonce, hash_val);

  clear(dest);
  size_t widx = 0; // What bit we are on for setting coefficient signs 
  size_t ridx = w_bytes; // Last read byte in buffer used for rejection sampling

  for (size_t idx = 0; idx < w; idx++) { 
    // Sample `n_bytes` from the output of the stream cipher 
    unsigned long cidx = 0;
    for (size_t tmp = 0; tmp < n_bytes; tmp++) {
      // Append the sampled byte to the end of our current output
      cidx <<= 8;
      cidx |= r[ridx++];

      // Loop back around if we run out of bytes (very unlikely)
      if (ridx == rlen) {
        ridx = w_bytes;  
      }
    }

    // Generate a random polynomial index by reducing the bytes by `n`
    cidx %= n;

    if (coeff(dest, cidx) == 0) {
      // Sample another random byte to determine if coefficient = -1 or 1 
      char bit = ((r[widx / 8] >> (widx % 8)) & 1);
      SetCoeff(dest, cidx, bit * 2 - 1); 
      widx++;
    }
    else {
      // The coefficient at this index has already been modified; repeat process
      idx--;
    }
  }
}
