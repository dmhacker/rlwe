#include "rlwe.hpp"

using namespace rlwe;

ZZX KeyParameters::EncodeInteger(const ZZ & plaintext) const {
  ZZX encoding = ZZX::zero();

  ZZ pos_one(1);
  ZZ neg_one(t - 1);

  for (long i = 0; i < NumBits(plaintext); i++) {
    if (bit(plaintext, i)) {
      SetCoeff(encoding, i, plaintext < 0 ? neg_one : pos_one);
    }
  }

  return encoding;
}

ZZ KeyParameters::DecodeInteger(const ZZX & encoding) const {
  ZZ plaintext = ZZ::zero();
  long sign = 1;

  for (long i = deg(encoding); i >= 0; i--) {
    plaintext <<= 1;

    ZZ coefficient = coeff(encoding, i);
    if (coefficient < 0 || coefficient > t / 2) {
      sign = -1;
    }
    if (coefficient != 0) {
      plaintext |= 1;
    }
  }

  return sign * plaintext;
}
