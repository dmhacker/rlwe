#include "newhope.h"
#include "sample.h"
#include "keccak-tiny.h"

#include <NTL/RR.h>
#include <cassert>

using namespace rlwe;
using namespace rlwe::newhope;

size_t CompressPolynomial(uint8_t * output, const ZZX & poly, size_t coeff_bit_length) {
  size_t i = 0; // Keeps track of what output byte we are on
  size_t bitpos = 0; // Keeps track of the bit position in the output byte

  // Read each coefficient in order, starting with x^0, then x^1, x^2, etc.
  for (size_t j = 0; j <= deg(poly); j++) {
    ZZ c = coeff(poly, j);

    // Loop through each bit in the coefficient starting with the LSB
    for (size_t k = 0; k < coeff_bit_length; k++) {
      // The mask is going to be a 1 bit in the position we want to edit
      uint8_t mask = 1 << (7 - bitpos++);

      // Set the bit in the output byte using the mask
      if (bit(c, k)) {
        output[i] |= mask;
      }
      else {
        output[i] &= ~mask;
      }

      // If the bit position is 8, we move to the next byte
      if (bitpos == 8) {
        i++;
        bitpos = 0; 
      }
    }
  }

  return i == 0 && bitpos == 0 ? 0 : i + 1;
}

void DecompressPolynomial(ZZX & poly, size_t polylen, const uint8_t * output, size_t coeff_bit_length) {
  clear(poly);

  size_t i = 0; // Keeps track of what output byte we are on
  size_t bitpos = 0; // Keeps track of the bit position in the output byte

  // Write each coefficient in order, starting with x^0, then x^1, x^2, etc.
  for (size_t j = 0; j < polylen; j++) {
    ZZ c;

    // Loop through bits in little endian fashion 
    for (size_t _ = 0; _ < coeff_bit_length; _++) {
      // Extract the bit from the output byte
      uint8_t byte = output[i];
      uint8_t bit = (byte >> (7 - bitpos++)) & 1;

      // Right shift coefficient to make room for new bit
      c <<= 1;
      if (bit) {
        c &= 1;
      }

      // If the bit position is 8, we move to the next byte
      if (bitpos == 8) {
        i++;
        bitpos = 0;
      }
    }

    SetCoeff(poly, j, c);
  }
}

void NHSEncode(ZZX & k, const uint8_t v[SHARED_KEY_BYTE_LENGTH], const ZZ & q) {
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

void NHSCompress(ZZX & cc, const ZZX & c, const ZZ & q) {
  clear(cc);

  for (size_t i = 0; i <= deg(c); i++) {
    SetCoeff(cc, i, ((coeff(c, i) * 8) / q) % 8);
  }
}

void NHSDecompress(ZZX & c, const ZZX & cc, const ZZ & q) {
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

void newhope::ReadPacket(Client & client, const uint8_t * packet) {
  const KeyParameters & params = client.GetParameters();

  // Set global finite field
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Copy the seed out of the packet
  uint8_t seed[SEED_BYTE_LENGTH];
  memcpy(seed, packet, SEED_BYTE_LENGTH);

  // Decode the compressed polynomial that follows the seed
  ZZX b;
  DecompressPolynomial(b, params.GetPolyModulusDegree(), packet + SEED_BYTE_LENGTH, NumBits(params.GetCoeffModulus()));

  // Parse seed into a polynomial 
  ZZX a;
  Parse(a, params.GetPolyModulusDegree(), params.GetCoeffModulus(), seed);

  // Convert ZZXs into their ZZ_pX equivalents
  ZZ_pX a_p = conv<ZZ_pX>(a);
  ZZ_pX b_p = conv<ZZ_pX>(b);
  ZZ_pX s_p = conv<ZZ_pX>(client.GetSecretKey());
  ZZ_pX e1_p = conv<ZZ_pX>(client.GetErrors().a);
  ZZ_pX e2_p = conv<ZZ_pX>(client.GetErrors().b);

  // u = a * s + e'
  ZZ_pX u_p;
  MulMod(u_p, a_p, s_p);
  u_p += e1_p;
  ZZX u = conv<ZZX>(u_p);

  // Generate client key by getting randomness from /dev/urandom
  uint8_t v[SHARED_KEY_BYTE_LENGTH];
  FILE * random_source = fopen("/dev/urandom", "r");
  assert(random_source != NULL);
  fread(v, sizeof(uint8_t), SHARED_KEY_BYTE_LENGTH, random_source);
  fclose(random_source);

  // v' = SHA3-256(v)
  sha3_256(v, SHARED_KEY_BYTE_LENGTH, v, SHARED_KEY_BYTE_LENGTH);

  // k = NHSEncode(v')
  ZZX k;
  NHSEncode(k, v, params.GetCoeffModulus());

  // c = b * s + e'' + k
  ZZ_pX c_p;
  MulMod(c_p, b_p, s_p, params.GetPolyModulus());
  c_p += e2_p;
  c_p += conv<ZZ_pX>(k);
  ZZX c = conv<ZZX>(c);

  // cc = NHSCompress(c)
  ZZX cc;
  NHSCompress(cc, c, params.GetCoeffModulus());

  // micro = SHA3-256(v')
  sha3_256(v, SHARED_KEY_BYTE_LENGTH, v, SHARED_KEY_BYTE_LENGTH);

  // Update client object with the new keys
  client.SetPublicKey(u);
  client.SetCiphertext(cc);
  client.SetSharedKey(v);
}

void newhope::ReadPacket(Server & server, const uint8_t * packet) {

}

void newhope::WritePacket(uint8_t * packet, const Server & server) {
  const KeyParameters & params = server.GetParameters();

  // Copy the seed into the packet first
  memcpy(packet, server.GetSeed(), SEED_BYTE_LENGTH);

  // Encode the polynomial immediately after
  CompressPolynomial(packet + SEED_BYTE_LENGTH, server.GetPublicKey(), NumBits(params.GetCoeffModulus()));
}

void newhope::WritePacket(uint8_t * packet, const Client & client) {
  
}
