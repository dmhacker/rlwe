#include "catch.hpp"
#include "../src/fv.hpp"
#include "../src/sampling.hpp"

using namespace rlwe;
using namespace rlwe::fv;

#include <NTL/ZZ_pX.h>

TEST_CASE("Experimental homomorphic key exchange") {
  KeyParameters params(1024, ZZ(12289), ZZ(2));
  KeyParameters leveled_params(params.GetPolyModulusDegree(), ZZ(2305843009213693951), params.GetCoeffModulus());

  NTL::ZZX a_shared = UniformSample(params.GetPolyModulusDegree(), ZZ(0), params.GetCoeffModulus()); 

  // Alice keeps these parameters private
  NTL::ZZX e_alice = GaussianSample(params.GetPolyModulusDegree(), params.GetErrorStandardDeviation());
  PrivateKey s_alice = params.GeneratePrivateKey();
  PrivateKey hs_alice = leveled_params.GeneratePrivateKey();

  // Alice publishes these parameters
  PublicKey p_alice = params.GeneratePublicKey(s_alice, a_shared, e_alice);
  PublicKey hp_alice = leveled_params.GeneratePublicKey(hs_alice);
  Ciphertext s_alice_encrypted_alice = hp_alice.Encrypt(Plaintext(s_alice.GetSecret(), leveled_params));

  // Bob keeps these parameters private
  NTL::ZZX e_bob = GaussianSample(params.GetPolyModulusDegree(), params.GetErrorStandardDeviation());
  PrivateKey s_bob = params.GeneratePrivateKey();
  PrivateKey hs_bob = leveled_params.GeneratePrivateKey();

  // Bob publishes these parameters
  PublicKey p_bob = params.GeneratePublicKey(s_bob, a_shared, e_bob);
  PublicKey hp_bob = leveled_params.GeneratePublicKey(hs_bob);
  Ciphertext s_bob_encrypted_bob = hp_bob.Encrypt(Plaintext(s_bob.GetSecret(), leveled_params));

  // Alice calculates this privately and then publishes the result
  Ciphertext key_bob_encrypted_bob = 
    (-hp_bob.Encrypt(Plaintext(p_bob.GetValues().a, leveled_params)) * hp_bob.Encrypt(Plaintext(s_alice.GetSecret(), leveled_params))) + 
    (hp_bob.Encrypt(Plaintext(e_alice, leveled_params)) * s_bob_encrypted_bob);

  // Bob calculates this privately and then publishes the result
  Ciphertext key_alice_encrypted_alice =
    (-hp_alice.Encrypt(Plaintext(p_alice.GetValues().a, leveled_params)) * hp_alice.Encrypt(Plaintext(s_bob.GetSecret(), leveled_params))) + 
    (hp_alice.Encrypt(Plaintext(e_bob, leveled_params)) * s_alice_encrypted_alice);

  // Alice decrypts Bob's computations to get her key
  Plaintext key_alice = hs_alice.Decrypt(key_alice_encrypted_alice);

  // Bob decrypts Alice's computations to get his key
  Plaintext key_bob = hs_bob.Decrypt(key_bob_encrypted_bob);

  REQUIRE(key_alice == key_bob);
}
