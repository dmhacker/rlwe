#include "catch.hpp"
#include "../src/rlwe.hpp"

TEST_CASE("Modulus is a cyclotomic polynomial") {
  rlwe::KeyParameters params(16, ZZ(874), ZZ(7));  

  NTL::ZZ_pPush push;
  NTL::ZZ_p::init(ZZ(874));

  NTL::ZZ_pX mod(INIT_MONO, 16);
  NTL::SetCoeff(mod, 0, 1);

  REQUIRE(mod == params.GetPolyModulus().val());
}

TEST_CASE("Private key is small polynomial") {
  rlwe::KeyParameters params(16, ZZ(874), ZZ(7));  
  rlwe::PrivateKey priv = params.GeneratePrivateKey();

  REQUIRE(NTL::deg(priv.GetS()) < params.GetPolyModulusDegree());

  for (long i = 0; i < params.GetPolyModulusDegree(); i++) {
    NTL::ZZ coefficient = NTL::coeff(priv.GetS(), i);
    REQUIRE(coefficient <= 1);
    REQUIRE(coefficient >= -1);
  }
}

TEST_CASE("Public key is computed correctly") {
  rlwe::KeyParameters params(8, ZZ(97), ZZ(2));  
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);

  NTL::ZZ_pPush push;
  NTL::ZZ_p::init(params.GetCoeffModulus());

  // Work out the error polynomial by computing -p0 - (p1 * s) = -b - (a * s)
  NTL::ZZ_pX buffer;
  MulMod(buffer, conv<NTL::ZZ_pX>(pub.GetP1()), conv<NTL::ZZ_pX>(priv.GetS()), params.GetPolyModulus());
  NTL::ZZ_pX error = -conv<NTL::ZZ_pX>(pub.GetP0()) - buffer;

  REQUIRE(NTL::deg(error) > 0);
}
