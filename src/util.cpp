#include "util.h"

#include <NTL/ZZ_pX.h>

void rlwe::RoundCoeffs(ZZX & poly, const RR scalar, const ZZ mod) {
  for (long i = 0; i <= deg(poly); i++) {
    RR rounded_coefficient = round(conv<RR>(coeff(poly, i)) * scalar); 
    SetCoeff(poly, i, conv<ZZ>(rounded_coefficient) % mod);
  }
}

void rlwe::TeslaRoundCoeffs(ZZX & c, const ZZ pow_2_d) {
  ZZ_pPush push;
  ZZ_p::init(pow_2_d);

  ZZX c_2_d = conv<ZZX>(conv<ZZ_pX>(c));
  rlwe::CenterCoeffs(c_2_d, pow_2_d); 

  c -= c_2_d;
  c /= pow_2_d;
}

void rlwe::CenterCoeffs(ZZX & poly, const ZZ mod) {
  ZZ center_point = mod / 2;
  for (long i = 0; i <= deg(poly); i++) {
    ZZ coefficient = coeff(poly, i);
    if (coefficient > center_point) {
      SetCoeff(poly, i, coefficient - mod);
    }
  }
}

bool rlwe::IsInRange(ZZX & poly, const ZZ bound) {
  for (long i = 0; i <= deg(poly); i++) {
    ZZ coefficient = coeff(poly, i);
    if (coefficient < -bound || coefficient > bound) {
      return 0;
    }
  }
  return 1;
}
