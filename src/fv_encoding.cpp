#include "fv.hpp"

using namespace rlwe::fv;

Plaintext KeyParameters::EncodeInteger(long integer) const {
  // Convert long into a NTL:ZZ big integer and defer to other function
  return EncodeInteger(ZZ(integer));
}

Plaintext KeyParameters::EncodeInteger(const ZZ & integer) const {
  ZZX encoding = ZZX::zero();

  ZZ global_coeff(1);
  if (integer < 0) {
    global_coeff = t - 1;
  }

  for (long i = 0; i < NumBits(integer); i++) {
    if (bit(integer, i)) {
      SetCoeff(encoding, i, global_coeff); 
    }
  }

  return Plaintext(encoding, *this);
}

ZZ KeyParameters::DecodeInteger(const Plaintext & encoding) const {
  ZZX message = encoding.GetMessage();
  ZZ integer = ZZ::zero();
  long sign = 1;

  for (long i = deg(message); i >= 0; i--) {
    integer <<= 1;

    ZZ coefficient = coeff(message, i);
    if (coefficient < 0 || coefficient > t / 2) {
      sign = -1;
    }
    if (coefficient != 0) {
      integer |= 1;
    }
  }

  return sign * integer;
}
