#include "catch.hpp"
#include "fv.h"
#include "sample.h"

using namespace rlwe;
using namespace rlwe::fv;

#include <NTL/ZZ_pX.h>

TEST_CASE("Experimental homomorphic key exchange") {
  KeyParameters params;
  KeyParameters leveled_params(params.GetPolyModulusDegree(), ZZ(2305843009213693951ULL), params.GetCoeffModulus());

  NTL::ZZX a_shared = UniformSample(params.GetPolyModulusDegree(), ZZ(0), params.GetCoeffModulus()); 

  // Alice keeps these parameters private
  NTL::ZZX e_alice = KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix(), params.GetProbabilityMatrixRows());
  PrivateKey s_alice = GeneratePrivateKey(params);
  PrivateKey hs_alice = GeneratePrivateKey(leveled_params);
  Plaintext ptx_s_alice(leveled_params);
  ptx_s_alice.SetMessage(s_alice.GetSecret());

  // Alice publishes these parameters
  PublicKey p_alice = GeneratePublicKey(s_alice, a_shared, e_alice);
  PublicKey hp_alice = GeneratePublicKey(hs_alice);
  Ciphertext s_alice_encrypted_alice = Encrypt(ptx_s_alice, hp_alice);

  // Bob keeps these parameters private
  NTL::ZZX e_bob = KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix(), params.GetProbabilityMatrixRows());
  PrivateKey s_bob = GeneratePrivateKey(params);
  PrivateKey hs_bob = GeneratePrivateKey(leveled_params);
  Plaintext ptx_s_bob(leveled_params);
  ptx_s_bob.SetMessage(s_bob.GetSecret());

  // Bob publishes these parameters
  PublicKey p_bob = GeneratePublicKey(s_bob, a_shared, e_bob);
  PublicKey hp_bob = GeneratePublicKey(hs_bob);
  Ciphertext s_bob_encrypted_bob = Encrypt(ptx_s_bob, hp_bob);

  // Alice calculates this privately and then publishes the result
  Plaintext ptx_p_bob(leveled_params);
  ptx_p_bob.SetMessage(p_bob.GetValues().a);
  Plaintext ptx_e_alice(leveled_params);
  ptx_e_alice.SetMessage(e_alice);
  Ciphertext key_bob_encrypted_bob = 
    (-Encrypt(ptx_p_bob, hp_bob) * Encrypt(ptx_s_alice, hp_bob)) + 
    (Encrypt(ptx_e_alice, hp_bob) * s_bob_encrypted_bob);

  // Bob calculates this privately and then publishes the result
  Plaintext ptx_p_alice(leveled_params);
  ptx_p_alice.SetMessage(p_alice.GetValues().a);
  Plaintext ptx_e_bob(leveled_params);
  ptx_e_bob.SetMessage(e_bob);
  Ciphertext key_alice_encrypted_alice =
    (-Encrypt(ptx_p_alice, hp_alice) * Encrypt(ptx_s_bob, hp_alice)) + 
    (Encrypt(ptx_e_bob, hp_alice) * s_alice_encrypted_alice);

  // Alice decrypts Bob's computations to get her key
  Plaintext key_alice = Decrypt(key_alice_encrypted_alice, hs_alice);

  // Bob decrypts Alice's computations to get his key
  Plaintext key_bob = Decrypt(key_bob_encrypted_bob, hs_bob);

  REQUIRE(key_alice == key_bob);
}
