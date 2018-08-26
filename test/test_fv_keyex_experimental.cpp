#include "catch.hpp"
#include "../src/fv.h"
#include "../src/sampling.h"

using namespace rlwe;
using namespace rlwe::fv;

#include <NTL/ZZ_pX.h>

TEST_CASE("Experimental homomorphic key exchange") {
  KeyParameters params(1024, 12289, 2);
  KeyParameters leveled_params(params.GetPolyModulusDegree(), conv<ZZ>("2305843009213693951"), params.GetCoeffModulus());

  NTL::ZZX a_shared = UniformSample(params.GetPolyModulusDegree(), ZZ(0), params.GetCoeffModulus()); 

  // Alice keeps these parameters private
  NTL::ZZX e_alice = KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix());
  PrivateKey s_alice = GeneratePrivateKey(params);
  PrivateKey hs_alice = GeneratePrivateKey(leveled_params);

  // Alice publishes these parameters
  PublicKey p_alice = GeneratePublicKey(s_alice, a_shared, e_alice);
  PublicKey hp_alice = GeneratePublicKey(hs_alice);
  Ciphertext s_alice_encrypted_alice = Encrypt(Plaintext(s_alice.GetSecret(), leveled_params), hp_alice);

  // Bob keeps these parameters private
  NTL::ZZX e_bob = KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix());
  PrivateKey s_bob = GeneratePrivateKey(params);
  PrivateKey hs_bob = GeneratePrivateKey(leveled_params);

  // Bob publishes these parameters
  PublicKey p_bob = GeneratePublicKey(s_bob, a_shared, e_bob);
  PublicKey hp_bob = GeneratePublicKey(hs_bob);
  Ciphertext s_bob_encrypted_bob = Encrypt(Plaintext(s_bob.GetSecret(), leveled_params), hp_bob);

  // Alice calculates this privately and then publishes the result
  Ciphertext key_bob_encrypted_bob = 
    (-Encrypt(Plaintext(p_bob.GetValues().a, leveled_params), hp_bob) * Encrypt(Plaintext(s_alice.GetSecret(), leveled_params), hp_bob)) + 
    (Encrypt(Plaintext(e_alice, leveled_params), hp_bob) * s_bob_encrypted_bob);

  // Bob calculates this privately and then publishes the result
  Ciphertext key_alice_encrypted_alice =
    (-Encrypt(Plaintext(p_alice.GetValues().a, leveled_params), hp_alice) * Encrypt(Plaintext(s_bob.GetSecret(), leveled_params), hp_alice)) + 
    (Encrypt(Plaintext(e_bob, leveled_params), hp_alice) * s_alice_encrypted_alice);

  // Alice decrypts Bob's computations to get her key
  Plaintext key_alice = Decrypt(key_alice_encrypted_alice, hs_alice);

  // Bob decrypts Alice's computations to get his key
  Plaintext key_bob = Decrypt(key_bob_encrypted_bob, hs_bob);

  REQUIRE(key_alice == key_bob);
}
