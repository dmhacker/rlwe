#include "fv.hpp"

using namespace rlwe;
using namespace rlwe::fv;

Plaintext fv::EncodeInteger(ZZ integer, const KeyParameters & params) {
  ZZX message;

  ZZ global_coeff(1);
  if (integer < 0) {
    global_coeff = params.GetPlainModulus() - 1;
  }

  for (long i = 0; i < NumBits(integer); i++) {
    if (bit(integer, i)) {
      SetCoeff(message, i, global_coeff); 
    }
  }

  return Plaintext(message, params);
}

ZZ fv::DecodeInteger(const Plaintext & plaintext, const KeyParameters & params) { 
  ZZ integer = ZZ::zero();
  long sign = 1;

  for (long i = deg(plaintext.GetMessage()); i >= 0; i--) {
    integer <<= 1;

    ZZ coefficient = coeff(plaintext.GetMessage(), i);
    if (coefficient < 0 || coefficient > params.GetPlainModulus() / 2) {
      sign = -1;
    }
    if (coefficient != 0) {
      integer |= 1;
    }
  }

  return sign * integer;
}
