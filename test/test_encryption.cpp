#include "catch.hpp"
#include "../src/rlwe.hpp"
#include "../src/sampling.hpp"

TEST_CASE("Encryption & decryption using small parameters") {
  // Set up parameters
  rlwe::KeyParameters params(16, 874, 7);  

  // Compute keys
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);

  // Generate random plaintext
  rlwe::Plaintext plaintext(rlwe::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert to ciphertext and then back to plaintext
  rlwe::Ciphertext ciphertext = pub.Encrypt(plaintext);
  rlwe::Plaintext decrypted = priv.Decrypt(ciphertext);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decrypted);
}

TEST_CASE("Encryption & decryption using large parameters") {
  // Set up parameters
  rlwe::KeyParameters params(4096, 9214347247561474048, 290764801);  

  // Compute keys
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);

  // Generate random plaintext
  rlwe::Plaintext plaintext(rlwe::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert to ciphertext and then back to plaintext
  rlwe::Ciphertext ciphertext = pub.Encrypt(plaintext);
  rlwe::Plaintext decrypted = priv.Decrypt(ciphertext);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decrypted);
}
