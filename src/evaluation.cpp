#include "rlwe.hpp"

#include <NTL/ZZ_pX.h>
#include <NTL/RR.h>

using namespace rlwe;

Ciphertext Ciphertext::Add(const Ciphertext & ct) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  ZZ_pX ct1_0 = conv<ZZ_pX>(c0);
  ZZ_pX ct1_1 = conv<ZZ_pX>(c1);

  ZZ_pX ct2_0 = conv<ZZ_pX>(ct.c0);
  ZZ_pX ct2_1 = conv<ZZ_pX>(ct.c1);

  ZZ_pX res_0 = ct1_0 + ct2_0;
  ZZ_pX res_1 = ct1_1 + ct2_1;

  return Ciphertext(conv<ZZX>(res_0), conv<ZZX>(res_1), params);
}

// TODO: Implement FV-style multiplication and immediate relinearization
Ciphertext Ciphertext::Multiply(const Ciphertext & ct) const {
  return ct;
}

