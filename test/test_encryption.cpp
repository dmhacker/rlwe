#include "catch.hpp"
#include "../src/rlwe.hpp"

TEST_CASE("Encryption & decryption work") {
  rlwe::KeyParameters params(16, ZZ(874), ZZ(7));  
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);

  NTL::ZZX plaintext;
  NTL::SetCoeff(plaintext, 0, 3);
  NTL::SetCoeff(plaintext, 2, 4);
  NTL::SetCoeff(plaintext, 5, 1);
  NTL::SetCoeff(plaintext, 7, 2);
  NTL::SetCoeff(plaintext, 8, 4);

  std::cerr << "Plaintext:" << std::endl;
  std::cerr << plaintext << std::endl;
  
  rlwe::Ciphertext ciphertext = pub.Encrypt(plaintext);

  std::cerr << "Ciphertext:" << std::endl;
  std::cerr << ciphertext.GetC0() << std::endl;
  std::cerr << ciphertext.GetC1() << std::endl;

  NTL::ZZX decrypted = priv.Decrypt(ciphertext);

  std::cerr << "Decrypted:" << std::endl;
  std::cerr << decrypted << std::endl;

  REQUIRE(plaintext == decrypted);
}
