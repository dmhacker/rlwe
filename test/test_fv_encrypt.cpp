#include "catch.hpp"
#include "fv.h"
#include "sample.h"

using namespace rlwe;
using namespace rlwe::fv;

TEST_CASE("Encryption & decryption using small parameters") {
  // Set up parameters
  KeyParameters params(16, 1337, 7);  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params);
  PublicKey pub = GeneratePublicKey(priv);

  // Generate random plaintext
  Plaintext ptx(params);
  ptx.SetMessage(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()));

  // Convert to ciphertext and then back to plaintext
  Ciphertext ctx = Encrypt(ptx, pub);
  Plaintext dptx = Decrypt(ctx, priv);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(ptx == dptx);
}

TEST_CASE("Encryption & decryption using large parameters") {
  // Set up parameters
  KeyParameters params(4096, conv<ZZ>("9214347247561474048"), ZZ(290764801));

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params);
  PublicKey pub = GeneratePublicKey(priv);

  // Generate random plaintext
  Plaintext ptx(params);
  ptx.SetMessage(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()));

  // Convert to ciphertext and then back to plaintext
  Ciphertext ctx = Encrypt(ptx, pub);
  Plaintext dptx = Decrypt(ctx, priv);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(ptx == dptx);
}
