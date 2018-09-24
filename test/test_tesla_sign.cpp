#include "catch.hpp"
#include "tesla.h"
#include "sample.h"

using namespace rlwe;
using namespace rlwe::tesla;

TEST_CASE("Verifying a signed message") {
  KeyParameters params;

  SigningKey signer = GenerateSigningKey(params);
  VerificationKey verif = GenerateVerificationKey(signer);

  Signature sig = Sign("test", signer);
  REQUIRE(Verify("test", sig, verif));
}

TEST_CASE("Verifying an incorrect message") {
  KeyParameters params;

  SigningKey signer = GenerateSigningKey(params);
  VerificationKey verif = GenerateVerificationKey(signer);

  Signature sig = Sign("test", signer);
  REQUIRE(!Verify("different", sig, verif));
}

TEST_CASE("Verifying an incorrect signature") {
  KeyParameters params;

  SigningKey signer = GenerateSigningKey(params);
  VerificationKey verif = GenerateVerificationKey(signer);

  Signature sig1 = Sign("test", signer);
  Signature sig2 = Sign("different", signer);
  REQUIRE(!Verify("test", sig2, verif));
}

