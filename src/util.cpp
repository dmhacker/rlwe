#include "util.hpp"

void rlwe::ScaleCoeffs(ZZX & poly, const RR scalar, const ZZ mod) {
  for (long i = 0; i <= deg(poly); i++) {
    RR rounded_coefficient = round(conv<RR>(coeff(poly, i)) * scalar); 
    SetCoeff(poly, i, conv<ZZ>(rounded_coefficient) % mod);
  }
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
