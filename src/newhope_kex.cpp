#include "newhope.h"
#include "sample.h"
#include "keccak-tiny.h"
#include "polyutil.h"

#include <cassert>

using namespace rlwe;
using namespace rlwe::newhope;

void newhope::WritePacket(Packet & packet, const Server & server) {
  const KeyParameters & params = server.GetParameters();

  // Copy the seed into the packet first
  memcpy(packet.GetBytes(), server.GetSeed(), SEED_BYTE_LENGTH);

  // Encode the polynomial immediately after
  CompressPolynomial(packet.GetBytes() + SEED_BYTE_LENGTH, server.GetPublicKey(), NumBits(params.GetCoeffModulus()));
}

void newhope::ReadPacket(Client & client, const Packet & packet) {
  const KeyParameters & params = client.GetParameters();

  // Set global finite field
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Copy the seed out of the packet
  uint8_t seed[SEED_BYTE_LENGTH];
  memcpy(seed, packet.GetBytes(), SEED_BYTE_LENGTH);

  // Decode the compressed polynomial that follows the seed
  ZZX b;
  DecompressPolynomial(b, params.GetPolyModulusDegree(), packet.GetBytes() + SEED_BYTE_LENGTH, NumBits(params.GetCoeffModulus()));

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
  MulMod(u_p, a_p, s_p, params.GetPolyModulus());
  u_p += e1_p;
  ZZX u = conv<ZZX>(u_p);

  // Generate client key by getting randomness from /dev/urandom
  uint8_t v[SHARED_KEY_BYTE_LENGTH];
  FILE * random_source = fopen("/dev/urandom", "r");
  assert(random_source != NULL);
  fread(v, 1, SHARED_KEY_BYTE_LENGTH, random_source);
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
  ZZX c = conv<ZZX>(c_p);

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

void newhope::WritePacket(Packet & packet, const Client & client) {
  const KeyParameters & params = client.GetParameters();

  // Encode the public key first
  size_t ulen = CompressPolynomial(packet.GetBytes(), client.GetPublicKey(), NumBits(params.GetCoeffModulus()));

  // Enocde the ciphertext next; since it is compressed, each coefficient only requires 3 bits
  CompressPolynomial(packet.GetBytes() + ulen, client.GetCiphertext(), 3); 
}

void newhope::ReadPacket(Server & server, const Packet & packet) {
  const KeyParameters & params = server.GetParameters();

  // Set global finite field
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Decode compressed public key 
  ZZX u;
  size_t ulen = DecompressPolynomial(u, params.GetPolyModulusDegree(), packet.GetBytes(), NumBits(params.GetCoeffModulus()));

  // Decode doubly-compressed ciphertext 
  ZZX cc;
  DecompressPolynomial(cc, params.GetPolyModulusDegree(), packet.GetBytes() + ulen, 3);

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

Packet newhope::CreatePacket(const Server & server) {
  const KeyParameters & params = server.GetParameters();

  // Calculate number of bytes needed to represent public key 
  size_t blen = params.GetPolyModulusDegree() * NumBits(params.GetCoeffModulus());
  blen = (blen + 8 - 1) / 8;

  // Allocate packet on the heap and write to it
  Packet packet(SEED_BYTE_LENGTH + blen);
  WritePacket(packet, server);

  return packet;
}

Packet newhope::CreatePacket(const Client & client) {
  const KeyParameters & params = client.GetParameters();

  // Calculate number of bytes needed to represent public key 
  size_t ulen = params.GetPolyModulusDegree() * NumBits(params.GetCoeffModulus());
  ulen = (ulen + 8 - 1) / 8;
  
  // Calculate number of bytes needed to represent compressed ciphertext
  size_t clen = params.GetPolyModulusDegree() * 3;
  clen = (clen + 8 - 1) / 8;

  // Allocate packet on the heap and write to it
  Packet packet(ulen + clen);
  WritePacket(packet, client);

  return packet;
}
