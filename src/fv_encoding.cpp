#include "fv.hpp"

using namespace rlwe::fv;

Plaintext::Plaintext(ZZ integer, const KeyParameters & params) : params(params) {
  ZZ global_coeff(1);
  if (integer < 0) {
    global_coeff = params.GetPlainModulus() - 1;
  }

  for (long i = 0; i < NumBits(integer); i++) {
    if (bit(integer, i)) {
      SetCoeff(m, i, global_coeff); 
    }
  }
}

ZZ Plaintext::ToInteger() const {
  ZZ integer = ZZ::zero();
  long sign = 1;

  for (long i = deg(m); i >= 0; i--) {
    integer <<= 1;

    ZZ coefficient = coeff(m, i);
    if (coefficient < 0 || coefficient > params.GetPlainModulus() / 2) {
      sign = -1;
    }
    if (coefficient != 0) {
      integer |= 1;
    }
  }

  return sign * integer;
}
