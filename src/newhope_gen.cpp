#include "newhope.h"
#include "sample.h"

#include <cassert>

using namespace rlwe;
using namespace rlwe::newhope;

void newhope::GenerateKeys(Server & server) {
  const KeyParameters & params = server.GetParameters();

  // Generate seed by getting randomness from /dev/urandom
  uint8_t seed[SEED_BYTE_LENGTH];
  FILE * random_source = fopen("/dev/urandom", "r");
  assert(random_source != NULL);
  fread(seed, sizeof(uint8_t), SEED_BYTE_LENGTH, random_source);
  fclose(random_source);

  // Parse seed into a polynomial
  ZZX a;
  Parse(a, seed);
  ZZ_pX a_p = conv<ZZ_pX>(a);

  // s <- Gaussian distribution
  ZZX s = KnuthYaoSample(params.GetPolyModulusDegree(), 
      params.GetProbabilityMatrix(), params.GetProbabilityMatrixRows());
  ZZ_pX s_p = conv<ZZ_pX>(s);

  // e <- Gaussian distribution
  ZZ_pX e_p = conv<ZZ_pX>(KnuthYaoSample(params.GetPolyModulusDegree(), 
        params.GetProbabilityMatrix(), params.GetProbabilityMatrixRows()));

  // b = a * s + e
  ZZ_pX b_p;
  MulMod(b_p, a_p, s_p, params.GetPolyModulus());
  b_p += e_p;
  ZZX b = conv<ZZX>(b_p);

  // Update the server object with the new keys
  server.SetSecretKey(s);
  server.SetPublicKey(b);
}

void newhope::GenerateKeys(Client & client) {
  const KeyParameters & params = client.GetParameters();

  // s <- Gaussian distribution
  client.SetSecretKey(
      KnuthYaoSample(
        params.GetPolyModulusDegree(), 
        params.GetProbabilityMatrix(), 
        params.GetProbabilityMatrixRows()));
}
