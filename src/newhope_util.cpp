#include "newhope.h"
#include "keccak-tiny.h"

using namespace rlwe;
using namespace rlwe::newhope;

void newhope::Parse(ZZX & a, size_t len, const ZZ & q, const uint8_t seed[SEED_BYTE_LENGTH]) {
  clear(a);

  // Generate an initial SHAKE-128 output that can be grown later
  size_t outlen = len % 2 == 0 ? len * 3 : len * 3 + 1;
  uint8_t * output = (uint8_t *) malloc(outlen * sizeof(uint8_t));
  shake128(output, outlen, seed, SEED_BYTE_LENGTH);

  size_t counter = 0;
  ZZ q5 = 5 * q;
  for (size_t idx = 0; idx < len; idx++) {
    while (1) {
      // Sample a 16-bit integer from the SHAKE-128 output
      uint16_t coeff = (output[counter] << 8) | output[counter + 1];
      counter += 2;

      // If we have exhausted our SHAKE-128 output, simply regrow it 
      if (counter == outlen) {
        outlen += 128;
        output = (uint8_t *) realloc(output, outlen);
        shake128(output, outlen, seed, SEED_BYTE_LENGTH);
      }

      // Only accept coefficients less than 5 * q
      if (coeff < q5) {
        SetCoeff(a, idx, coeff);
        break;
      }
    }
  }

  // Free our output array
  free(output);
}
