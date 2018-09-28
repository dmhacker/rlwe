#include "newhope.h"
#include "sample.h"

#include <cassert>
#include <sodium.h>

using namespace rlwe;
using namespace rlwe::newhope;

void newhope::Initialize(Server & server) {
  const KeyParameters & params = server.GetParameters();

  // Set global finite field
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Generate seed by getting randomness from /dev/urandom
  uint8_t seed[SEED_BYTE_LENGTH];
  randombytes_buf(seed, SEED_BYTE_LENGTH);

  // Parse seed into a polynomial
  ZZX a;
  Parse(a, params.GetPolyModulusDegree(), params.GetCoeffModulus(), seed);
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
  server.SetSeed(seed);
  server.SetSecretKey(s);
  server.SetPublicKey(b);
}

void newhope::Initialize(Client & client) {
  const KeyParameters & params = client.GetParameters();

  // s <- Gaussian distribution
  client.SetSecretKey(
      KnuthYaoSample(
        params.GetPolyModulusDegree(), 
        params.GetProbabilityMatrix(), 
        params.GetProbabilityMatrixRows()));

  // e1, e2 <- Gaussian distribution 
  client.SetErrors(
      KnuthYaoSample(
        params.GetPolyModulusDegree(), 
        params.GetProbabilityMatrix(), 
        params.GetProbabilityMatrixRows()), 
      KnuthYaoSample(
        params.GetPolyModulusDegree(), 
        params.GetProbabilityMatrix(), 
        params.GetProbabilityMatrixRows()));
}

Server newhope::CreateServer(const KeyParameters & params) {
  Server server(params);
  Initialize(server);
  return server;
}

Client newhope::CreateClient(const KeyParameters & params) {
  Client client(params);
  Initialize(client);
  return client;
}
