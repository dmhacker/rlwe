#include "fv.h"

#include <cassert>

using namespace rlwe;
using namespace rlwe::fv;

Plaintext fv::EncodeInteger(long integer, const KeyParameters & params) {
  return EncodeInteger(ZZ(integer), params);  
}

Plaintext fv::EncodeInteger(long integer, unsigned long base, const KeyParameters & params) {
  return EncodeInteger(ZZ(integer), base, params);  
}

Plaintext fv::EncodeInteger(const ZZ & integer, const KeyParameters & params) {
  // Setup variables
  ZZX message;

  // Translate the absolute value of the integer into a polynomial
  for (int i = 0; i < NumBits(integer); i++) {
    if (bit(integer, i)) {
      SetCoeff(message, i, 1); 
    }
  }

  // For negative integers, flip the signs of all of the coefficients
  if (integer < 0) {
    message *= params.GetPlainModulus() - 1;
  }

  return Plaintext(message, params);
}

Plaintext fv::EncodeInteger(const ZZ & integer, unsigned long base, const KeyParameters & params) {
  assert(base > 1);

  // Use binary encoding algorithm if base is 2
  if (base == 2) {
    return EncodeInteger(integer, params);
  }

  // Setup variables 
  ZZX message;
  ZZ absval; 
  ZZ digit;
  int i = 0;
  abs(absval, integer);

  // Write out the integer in `base` and set coefficients accordingly
  while (absval > 0) {
    SetCoeff(message, i, absval % base); 
    absval /= base;
    i++;
  }

  // For negative integers, add plaintext modulus to each coefficient * -1
  if (integer < 0) {
    for (i = 0; i <= deg(message); i++) {
      SetCoeff(message, i, params.GetPlainModulus() - coeff(message, i));
    }
  }

  return Plaintext(message, params);
}

ZZ fv::DecodeInteger(const Plaintext & plaintext) { 
  return DecodeInteger(plaintext, (unsigned long) 2);
}

ZZ fv::DecodeInteger(const Plaintext & plaintext, unsigned long base) { 
  assert(base > 1);

  // Sum starts out at zero, x variable starts out at 1
  ZZ sum = ZZ::zero();
  ZZ x = sum + 1; 

  // Any coefficients greater than the center are flipped
  const ZZ & t = plaintext.GetParameters().GetPlainModulus();
  ZZ center_point = t / 2; 

  for (int i = 0; i <= deg(plaintext.GetMessage()); i++) {
    // Compute a centered coefficient from the original one
    ZZ scalar = coeff(plaintext.GetMessage(), i);
    if (scalar > center_point) {
      scalar -= t; 
    }

    // Add a scaled version of x to the sum
    sum += scalar * x;

    // x increases by a factor of the given base 
    x *= base;
  }

  return sum;
}
