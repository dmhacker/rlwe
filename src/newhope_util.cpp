#include "newhope.h"
#include "keccak-tiny.h"

#include <NTL/RR.h>

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

void newhope::NHSEncode(ZZX & k, const uint8_t v[SHARED_KEY_BYTE_LENGTH], const ZZ & q) {
  clear(k);

  ZZ q2 = q / 2;

  // Loop through each byte
  for (size_t i = 0; i < SHARED_KEY_BYTE_LENGTH; i++) {
    uint8_t byte = v[i];

    // Loop through each bit 
    for (size_t j = 0; j < 8; j++) {
      size_t b = i * 8 + j;

      // Set floor(q / 2) as coefficient if bit is 1, otherwise 0 is coefficient 
      if ((byte >> (7 - j)) & 1) {
        SetCoeff(k, b, q2);
        SetCoeff(k, b + 256, q2);
        SetCoeff(k, b + 512, q2);
        SetCoeff(k, b + 768, q2);
      }
      else {
        SetCoeff(k, b, 0);
        SetCoeff(k, b + 256, 0);
        SetCoeff(k, b + 512, 0);
        SetCoeff(k, b + 768, 0);
      }
    }
  }
}

void newhope::NHSDecode(uint8_t v[SHARED_KEY_BYTE_LENGTH], const ZZX & k, const ZZ & q) {
  for (size_t i = 0; i < 256; i++) {
    // t = sum(v[i + 256 * j] - floor(q / 2)] 
    ZZ t = -2 * q;
    for (size_t j = 0; j < 4; j++) {
      t += coeff(k, i + 256 * j);
    }

    // If t < q, then set bit to 1, otherwise set bit to 0
    uint8_t mask = 1 << (7 - i % 8);
    if (t < q) {
      v[i / 8] |= mask; 
    }
    else {
      v[i / 8] &= ~mask;
    }
  }
}

void newhope::NHSCompress(ZZX & cc, const ZZX & c, const ZZ & q) {
  clear(cc);

  for (size_t i = 0; i <= deg(c); i++) {
    SetCoeff(cc, i, ((coeff(c, i) * 8) / q) % 8);
  }
}

void newhope::NHSDecompress(ZZX & c, const ZZX & cc, const ZZ & q) {
  clear(c);

  RR r;
  for (size_t i = 0; i <= deg(cc); i++) {
    // Convert coefficient to decimal version and perform rounding operation
    ZZ z = coeff(cc, i) * q;
    conv(r, z);
    r /= 8;
    round(r, r);

    // Convert rounded coefficient back to integer equivalent 
    conv(z, r);
    SetCoeff(c, i, z);
  }
}
