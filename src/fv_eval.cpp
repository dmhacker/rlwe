#include "fv.h"
#include "polyutil.h"

#include <cassert>

using namespace rlwe::fv;

Ciphertext & Ciphertext::Negate() {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  Vec<ZZX> c_new;
  c_new.SetLength(c.length());
  for (long index = 0; index < c.length(); index++) {
    ZZ_pX inverted = -conv<ZZ_pX>(c[index]);
    c_new[index] = conv<ZZX>(inverted);
  }

  this->c = c_new;

  return *this; 
}

Ciphertext & Ciphertext::operator+= (const Ciphertext & ct) {
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

  this->c = c_new;

  return *this; 
}

Ciphertext & Ciphertext::operator*= (const Ciphertext & ct) {
  // Get ciphertext sizes
  long j = c.length() - 1;
  long k = ct.c.length() - 1;

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
    RoundCoeffs(sum, sum, params.GetCoeffToPlainScalar(), params.GetCoeffModulus());

    // Add sum to ciphertext
    c_new[m] = sum;
  }

  this->c = c_new;

  return *this; 
}

Ciphertext & Ciphertext::Relinearize(const EvaluationKey & elk) {
  if (c.length() <= 2) {
    return *this;
  }

  long k = c.length() - 1; 
  assert(elk.GetLevel() == k);

  Vec<ZZX> c_new;
  c_new.SetLength(k);

  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  ZZ_pX c0_addition;
  ZZ_pX c1_addition;
  ZZ_pX buffer;

  ZZX ck = c[k];
  ZZX decomposition; 

  for (long i = 0; i <= params.GetDecompositionTermCount(); i++) {
    for (long j = 0; j <= deg(ck); j++) {
      SetCoeff(decomposition, j, ck[j] & params.GetDecompositionBitMask());
      SetCoeff(ck, j, ck[j] >>= params.GetDecompositionBitCount());
    }

    MulMod(buffer, conv<ZZ_pX>(elk[i].a), conv<ZZ_pX>(decomposition), params.GetPolyModulus());
    c0_addition += buffer;

    MulMod(buffer, conv<ZZ_pX>(elk[i].b), conv<ZZ_pX>(decomposition), params.GetPolyModulus());
    c1_addition += buffer;
  }

  c_new[0] = conv<ZZX>(conv<ZZ_pX>(c[0]) + c0_addition);
  c_new[1] = conv<ZZX>(conv<ZZ_pX>(c[1]) + c1_addition);
  for (long i = 2; i < k; i++) {
    c_new[i] = c[i];
  }

  this->c = c_new;

  return *this;
}
