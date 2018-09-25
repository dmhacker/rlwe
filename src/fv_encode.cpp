#include "fv.h"

#include <cassert>

using namespace rlwe;
using namespace rlwe::fv;

void fv::EncodeInteger(Plaintext & ptx, long integer) {
  EncodeInteger(ptx, ZZ(integer));  
}

void fv::EncodeInteger(Plaintext & ptx, long integer, unsigned long base) {
  EncodeInteger(ptx, ZZ(integer), base);  
}

void fv::EncodeInteger(Plaintext & ptx, const ZZ & integer) {
  const KeyParameters & params = ptx.GetParameters(); 

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

  ptx.SetMessage(message);
}

void fv::EncodeInteger(Plaintext & ptx, const ZZ & integer, unsigned long base) {
  assert(base > 1);
  const KeyParameters & params = ptx.GetParameters(); 

  // Use binary encoding algorithm if base is 2
  if (base == 2) {
    EncodeInteger(ptx, integer);
    return;
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

  ptx.SetMessage(message);
}

void fv::DecodeInteger(ZZ & integer, const Plaintext & plaintext) { 
  DecodeInteger(integer, plaintext, (unsigned long) 2);
}

void fv::DecodeInteger(ZZ & integer, const Plaintext & plaintext, unsigned long base) { 
  assert(base > 1);

  // Sum starts out at zero, x variable starts out at 1
  clear(integer);
  ZZ x = integer + 1; 

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
    integer += scalar * x;

    // x increases by a factor of the given base 
    x *= base;
  }
}

Plaintext fv::EncodeInteger(long integer, const KeyParameters & params) {
  Plaintext ptx(params);
  EncodeInteger(ptx, ZZ(integer));
  return ptx;
}

Plaintext fv::EncodeInteger(long integer, unsigned long base, const KeyParameters & params) {
  Plaintext ptx(params);
  EncodeInteger(ptx, ZZ(integer), base);
  return ptx;
}

Plaintext fv::EncodeInteger(const ZZ & integer, const KeyParameters & params) {
  Plaintext ptx(params);
  EncodeInteger(ptx, integer); 
  return ptx;
}

Plaintext fv::EncodeInteger(const ZZ & integer, unsigned long base, const KeyParameters & params) {
  Plaintext ptx(params);
  EncodeInteger(ptx, integer, base); 
  return ptx;
}

ZZ fv::DecodeInteger(const Plaintext & ptx) {
  ZZ integer;
  DecodeInteger(integer, ptx);
  return integer;
}

ZZ fv::DecodeInteger(const Plaintext & ptx, unsigned long base) {
  ZZ integer;
  DecodeInteger(integer, ptx, base);
  return integer;
}
