#include "rlwe.hpp"

#include <NTL/RR.h>

using namespace rlwe;

ZZX util::ScaleCoeffs(const ZZX & poly, const ZZ numer, const ZZ denom, const ZZ mod) {
  ZZX result;
  RR scalar = conv<RR>(numer) / conv<RR>(denom);
  for (long i = 0; i <= deg(poly); i++) {
    ZZ coefficient = coeff(poly, i);
    RR rounded_coefficient = round(conv<RR>(coefficient) * scalar); 
    SetCoeff(result, i, conv<ZZ>(rounded_coefficient));
  }
  return result;
}

void util::ScaleCoeffs(ZZX & poly, const ZZ numer, const ZZ denom, const ZZ mod) {
  RR scalar = conv<RR>(numer) / conv<RR>(denom);
  for (long i = 0; i <= deg(poly); i++) {
    ZZ coefficient = coeff(poly, i);
    RR rounded_coefficient = round(conv<RR>(coefficient) * scalar); 
    SetCoeff(poly, i, conv<ZZ>(rounded_coefficient) % mod);
  }
}

void util::CenterCoeffs(ZZX & poly, const ZZ mod) {
  ZZ center_point = mod / 2;
  for (long i = 0; i <= deg(poly); i++) {
    ZZ coefficient = coeff(poly, i);
    if (coefficient > center_point) {
      SetCoeff(poly, i, coefficient - mod);
    }
  }
}
