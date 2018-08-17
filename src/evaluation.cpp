#include "rlwe.hpp"

#include <NTL/ZZ_pX.h>
#include <NTL/RR.h>
#include <cassert>

using namespace rlwe;

Ciphertext Ciphertext::Add(const Ciphertext & ct) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Find minimum and maximum lengths of ciphertexts
  long minlen;
  long maxlen;
  if (c.length() < ct.c.length()) {
    minlen = c.length();
    maxlen = ct.c.length();
  }
  else {
    minlen = ct.c.length();
    maxlen = c.length();
  }
  const Vec<ZZX> & longer = c.length() > ct.c.length() ? c : ct.c;

  // Set up vector for new ciphertext
  Vec<ZZX> c_new;
  c_new.SetLength(maxlen);
  long index = 0;

  // Add together any terms we can 
  for (;index < minlen; index++) {
    ZZ_pX c0 = conv<ZZ_pX>(c[index]);
    ZZ_pX c1 = conv<ZZ_pX>(ct.c[index]);

    c_new[index] = conv<ZZX>(c0 + c1);
  }

  // Any terms that we can't add, we just copy over
  for (;index < maxlen; index++) {
    c_new[index] = longer[index];
  }

  return Ciphertext(c_new, params);
}

// TODO: Extend multiplication to more than just the first two terms
Ciphertext Ciphertext::Multiply(const Ciphertext & ct) const {
  assert(c.length() == 2 && ct.c.length() == 2);

  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Create lifted versions of c0, c1, c2
  ZZX c0_ct1 = conv<ZZX>(c[0]);
  ZZX c0_ct2 = conv<ZZX>(ct.c[0]);
  ZZX c1_ct1 = conv<ZZX>(c[1]);
  ZZX c1_ct2 = conv<ZZX>(ct.c[1]);

  // Compute new c0, c1, c2
  ZZX c0_lifted;
  ZZX c1_lifted;
  ZZX c2_lifted;
  ZZX buffer;

  ZZX tmp_modulus = conv<ZZX>(params.GetPolyModulus().val()); 

  MulMod(c0_lifted, c0_ct1, c0_ct2, tmp_modulus);

  MulMod(c1_lifted, c0_ct1, c1_ct2, tmp_modulus); 
  MulMod(buffer, c1_ct1, c0_ct2, tmp_modulus); 
  c1_lifted += buffer;

  MulMod(c2_lifted, c1_ct1, c1_ct2, tmp_modulus); 

  // Remove extra scaling on message in ciphertext
  util::ScaleCoeffs(c0_lifted, params.GetPlainModulus(), params.GetCoeffModulus(), params.GetCoeffModulus());
  util::ScaleCoeffs(c1_lifted, params.GetPlainModulus(), params.GetCoeffModulus(), params.GetCoeffModulus());
  util::ScaleCoeffs(c2_lifted, params.GetPlainModulus(), params.GetCoeffModulus(), params.GetCoeffModulus());

  // Convert lifted polynomials back to finite field
  ZZ_pX c0_new = conv<ZZ_pX>(c0_lifted);
  ZZ_pX c1_new = conv<ZZ_pX>(c1_lifted);
  ZZ_pX c2_new = conv<ZZ_pX>(c2_lifted);

  Vec<ZZX> c_new; 
  c_new.SetLength(3);
  c_new[0] = conv<ZZX>(c0_new);
  c_new[1] = conv<ZZX>(c1_new);
  c_new[2] = conv<ZZX>(c2_new);

  return Ciphertext(c_new, params);
}

// TODO: Implement relinearization process
Ciphertext Ciphertext::Relinearize(const EvaluationKey & elk) const {
  return *this;
}
