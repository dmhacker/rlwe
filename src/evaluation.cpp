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

Ciphertext Ciphertext::Multiply(const Ciphertext & ct) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Get ciphertext sizes
  long j = length() - 1;
  long k = ct.length() - 1;

  // Set up a buffer for storing MulMods and a buffer for storing the poly modulus
  ZZX buffer = ZZX::zero();
  ZZX tmp_modulus = conv<ZZX>(params.GetPolyModulus().val()); 

  // Create the resultant ciphertext vector
  Vec<ZZX> c_new; 
  c_new.SetLength(j + k + 1);

  for (long m = 0; m < c_new.length(); m++) {
    // Calculate sum of multiplied ciphertext terms 
    ZZX sum = ZZX::zero();
    for (long r = 0; r <= m; r++) {
      long s = m - r;
      if (r <= j && s <= k) {
        MulMod(buffer, c[r], ct.c[s], tmp_modulus);
        sum += buffer;
      }
    }

    // Perform downscale to get rid of extra message scaling 
    util::ScaleCoeffs(sum, params.GetPlainModulus(), params.GetCoeffModulus(), params.GetCoeffModulus());

    // Add sum to ciphertext
    c_new[m] = sum;
  }

  return Ciphertext(c_new, params);
}

// TODO: Implement relinearization process
Ciphertext Ciphertext::Relinearize(const EvaluationKey & elk) const {
  return *this;
}
