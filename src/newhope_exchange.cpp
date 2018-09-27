#include "newhope.h"
#include "sample.h"
#include "keccak-tiny.h"

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

size_t DecompressPolynomial(ZZX & poly, size_t polylen, const uint8_t * output, size_t coeff_bit_length) {
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

  return i == 0 && bitpos == 0 ? 0 : i + 1;
}

void newhope::WritePacket(uint8_t * packet, const Server & server) {
  const KeyParameters & params = server.GetParameters();

  // Copy the seed into the packet first
  memcpy(packet, server.GetSeed(), SEED_BYTE_LENGTH);

  // Encode the polynomial immediately after
  CompressPolynomial(packet + SEED_BYTE_LENGTH, server.GetPublicKey(), NumBits(params.GetCoeffModulus()));
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

void newhope::WritePacket(uint8_t * packet, const Client & client) {
  const KeyParameters & params = client.GetParameters();

  // Encode the public key first
  size_t ulen = CompressPolynomial(packet, client.GetPublicKey(), NumBits(params.GetCoeffModulus()));

  // Enocde the ciphertext next; since it is compressed, each coefficient only requires 3 bits
  CompressPolynomial(packet + ulen, client.GetCiphertext(), 3); 
}

void newhope::ReadPacket(Server & server, const uint8_t * packet) {
  const KeyParameters & params = server.GetParameters();

  // Set global finite field
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Decode compressed public key 
  ZZX u;
  size_t ulen = DecompressPolynomial(u, params.GetPolyModulusDegree(), packet, NumBits(params.GetCoeffModulus()));

  // Decode doubly-compressed ciphertext 
  ZZX cc;
  DecompressPolynomial(cc, params.GetPolyModulusDegree(), packet + ulen, 3);

  // Decompress ciphertext
  ZZX c;
  NHSDecompress(c, cc, params.GetCoeffModulus());

  // Convert ZZXs into their ZZ_pX equivalents
  ZZ_pX u_p = conv<ZZ_pX>(u);
  ZZ_pX c_p = conv<ZZ_pX>(c);
  ZZ_pX s_p = conv<ZZ_pX>(server.GetSecretKey());

  // k' = c' - u * s
  ZZ_pX k_p;
  MulMod(k_p, u_p, s_p, params.GetPolyModulus());
  k_p *= -1;
  k_p += c_p;
  ZZX k = conv<ZZX>(k_p);

  // v' = NHSDecode(k')
  uint8_t v[SHARED_KEY_BYTE_LENGTH];
  NHSDecode(v, k, params.GetCoeffModulus());

  // micro = SHA3-256(v')
  sha3_256(v, SHARED_KEY_BYTE_LENGTH, v, SHARED_KEY_BYTE_LENGTH);

  // Update client object with the shared key 
  server.SetSharedKey(v);
}
