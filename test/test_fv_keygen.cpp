#include "catch.hpp"
#include "../src/fv.hpp"

using namespace rlwe::fv;

TEST_CASE("Modulus is a cyclotomic polynomial") {
  KeyParameters params(16, 874, 7);  

  NTL::ZZ_pPush push;
  NTL::ZZ_p::init(ZZ(874));

  NTL::ZZ_pX mod(INIT_MONO, 16);
  NTL::SetCoeff(mod, 0, 1);

  REQUIRE(mod == params.GetPolyModulus().val());
}

TEST_CASE("Private key is small polynomial") {
  KeyParameters params(16, 874, 7);  
  PrivateKey priv(params);

  REQUIRE(NTL::deg(priv.GetSecret()) < params.GetPolyModulusDegree());

  for (long i = 0; i < params.GetPolyModulusDegree(); i++) {
    NTL::ZZ coefficient = NTL::coeff(priv.GetSecret(), i);
    if (coefficient > params.GetCoeffModulus() / 2) { 
      REQUIRE(coefficient == params.GetCoeffModulus() - 1); 
    }
    else if (coefficient > 0) {
      REQUIRE(coefficient == 1);
    }
  }
}

TEST_CASE("Public key is computed correctly") {
  KeyParameters params(16, 874, 7);  
  PrivateKey priv(params);
  PublicKey pub(priv);

  NTL::ZZ_pPush push;
  NTL::ZZ_p::init(params.GetCoeffModulus());

  NTL::ZZ_pX buffer;
  Pair<NTL::ZZX, NTL::ZZX> pub_pair = pub.GetValues();
  MulMod(buffer, conv<NTL::ZZ_pX>(pub_pair.b), conv<NTL::ZZ_pX>(priv.GetSecret()), params.GetPolyModulus());
  NTL::ZZ_pX error = -conv<NTL::ZZ_pX>(pub_pair.a) - buffer;

  REQUIRE(NTL::deg(error) > 0);
}
