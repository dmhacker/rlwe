#include "catch.hpp"
#include "../src/rlwe.hpp"

#include <NTL/ZZ_pX.h>

TEST_CASE("Experimental homomorphic key exchange") {
  rlwe::KeyParameters params(1024, ZZ(12289), ZZ(2));
  rlwe::KeyParameters leveled_params(params.GetPolyModulusDegree(), ZZ(2305843009213693951), params.GetCoeffModulus());

  NTL::ZZX a_shared = rlwe::random::UniformSample(params.GetPolyModulusDegree(), ZZ(0), params.GetCoeffModulus()); 

  // Alice keeps these parameters private
  NTL::ZZX e_alice = rlwe::random::GaussianSample(params.GetPolyModulusDegree(), params.GetErrorStandardDeviation());
  rlwe::PrivateKey s_alice = params.GeneratePrivateKey();
  rlwe::PrivateKey hs_alice = leveled_params.GeneratePrivateKey();

  // Alice publishes these parameters
  rlwe::PublicKey p_alice = params.GeneratePublicKey(s_alice, a_shared, e_alice);
  rlwe::PublicKey hp_alice = leveled_params.GeneratePublicKey(hs_alice);
  rlwe::Ciphertext s_alice_encrypted_alice = hp_alice.Encrypt(rlwe::Plaintext(s_alice.GetS(), leveled_params));

  // Bob keeps these parameters private
  NTL::ZZX e_bob = rlwe::random::GaussianSample(params.GetPolyModulusDegree(), params.GetErrorStandardDeviation());
  rlwe::PrivateKey s_bob = params.GeneratePrivateKey();
  rlwe::PrivateKey hs_bob = leveled_params.GeneratePrivateKey();

  // Bob publishes these parameters
  rlwe::PublicKey p_bob = params.GeneratePublicKey(s_bob, a_shared, e_bob);
  rlwe::PublicKey hp_bob = leveled_params.GeneratePublicKey(hs_bob);
  rlwe::Ciphertext s_bob_encrypted_bob = hp_bob.Encrypt(rlwe::Plaintext(s_bob.GetS(), leveled_params));

  // Alice calculates this privately and then publishes the result
  rlwe::Ciphertext key_bob_encrypted_bob = 
    (hp_bob.Encrypt(rlwe::Plaintext(p_bob.GetP0(), leveled_params)).Negate() * hp_bob.Encrypt(rlwe::Plaintext(s_alice.GetS(), leveled_params))) + 
    (hp_bob.Encrypt(rlwe::Plaintext(e_alice, leveled_params)) * s_bob_encrypted_bob);

  // Bob calculates this privately and then publishes the result
  rlwe::Ciphertext key_alice_encrypted_alice =
    (hp_alice.Encrypt(rlwe::Plaintext(p_alice.GetP0(), leveled_params)).Negate() * hp_alice.Encrypt(rlwe::Plaintext(s_bob.GetS(), leveled_params))) + 
    (hp_alice.Encrypt(rlwe::Plaintext(e_bob, leveled_params)) * s_alice_encrypted_alice);

  // Alice decrypts Bob's computations to get her key
  rlwe::Plaintext key_alice = hs_alice.Decrypt(key_alice_encrypted_alice);

  // Bob decrypts Alice's computations to get his key
  rlwe::Plaintext key_bob = hs_bob.Decrypt(key_bob_encrypted_bob);

  REQUIRE(key_alice == key_bob);
}
