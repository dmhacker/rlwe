#include "catch.hpp"
#include "fv.h" 
#include "sample.h"

#include <NTL/ZZ_pX.h>

using namespace rlwe;
using namespace rlwe::fv;

TEST_CASE("Homomorphic addition") {
  // Set up parameters
  KeyParameters params(1024, 12289, 2);  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params);
  PublicKey pub = GeneratePublicKey(priv);

  // Generate two random plaintexts
  Plaintext ptx1(params);
  ptx1.SetMessage(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()));
  Plaintext ptx2(params);
  ptx2.SetMessage(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()));

  // Convert both to ciphertexts 
  Ciphertext ctx1 = Encrypt(ptx1, pub);
  Ciphertext ctx2 = Encrypt(ptx2, pub);

  // Perform homomorphic addition
  Ciphertext ctx = ctx1 + ctx2;

  // Decrypt resultant ciphertext
  Plaintext ptx = Decrypt(ctx, priv);

  // Compute the additions in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p = conv<ZZ_pX>(ptx1.GetMessage()) + conv<ZZ_pX>(ptx2.GetMessage());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(ptx.GetMessage() == m);
}

