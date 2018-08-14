#include "rlwe.hpp"

#include <NTL/ZZ_pX.h>
#include <NTL/RR.h>

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

// TODO: Figure out why multiplication is failing
Ciphertext Ciphertext::Multiply(const Ciphertext & ct) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  std::cerr << *this << std::endl;
  std::cerr << ct << std::endl;
  std::cerr << params.GetCoeffModulus() << std::endl;

  // Compute centered versions of c0, c1, c2
  ZZX c0_ct1 = conv<ZZX>(c[0]);
  ZZX c0_ct2 = conv<ZZX>(ct.c[0]);
  ZZX c1_ct1 = conv<ZZX>(c[1]);
  ZZX c1_ct2 = conv<ZZX>(ct[1]);
  util::CenterCoeffs(c0_ct1, params.GetCoeffModulus()); 
  util::CenterCoeffs(c0_ct2, params.GetCoeffModulus()); 
  util::CenterCoeffs(c1_ct1, params.GetCoeffModulus()); 
  util::CenterCoeffs(c1_ct2, params.GetCoeffModulus()); 

  std::cerr << c0_ct1 << std::endl;
  std::cerr << c0_ct2 << std::endl;
  std::cerr << c1_ct1 << std::endl;
  std::cerr << c1_ct2 << std::endl;

  // Compute new c0, c1, c2
  ZZX c0_new;
  ZZX c1_new;
  ZZX c2_new;
  ZZX buffer;

  ZZX tmp_modulus = conv<ZZX>(params.GetPolyModulus().val()); 

  MulMod(c0_new, c0_ct1, c0_ct2, tmp_modulus);

  MulMod(c1_new, c0_ct1, c1_ct2, tmp_modulus); 
  MulMod(buffer, c1_ct1, c0_ct2, tmp_modulus); 
  c1_new += buffer;

  MulMod(c2_new, c1_ct1, c1_ct2, tmp_modulus); 

  std::cerr << c0_new << std::endl;
  std::cerr << c1_new << std::endl;
  std::cerr << c2_new << std::endl;

  // Remove extra scaling on message in ciphertext
  ZZ_pX c0_new_p = conv<ZZ_pX>(util::ScaleCoeffs(conv<ZZX>(c0_new), params.GetPlainModulus(), params.GetCoeffModulus(), params.GetCoeffModulus()));
  ZZ_pX c1_new_p = conv<ZZ_pX>(util::ScaleCoeffs(conv<ZZX>(c1_new), params.GetPlainModulus(), params.GetCoeffModulus(), params.GetCoeffModulus()));
  ZZ_pX c2_new_p = conv<ZZ_pX>(util::ScaleCoeffs(conv<ZZX>(c2_new), params.GetPlainModulus(), params.GetCoeffModulus(), params.GetCoeffModulus()));

  std::cerr << c0_new_p << std::endl;
  std::cerr << c1_new_p << std::endl;
  std::cerr << c2_new_p << std::endl;

  Vec<ZZX> c_new; 
  c_new.SetLength(3);
  c_new[0] = conv<ZZX>(c0_new_p);
  c_new[1] = conv<ZZX>(c1_new_p);
  c_new[2] = conv<ZZX>(c2_new_p);

  return Ciphertext(c_new, params);
}

// TODO: Implement relinearization process
Ciphertext Ciphertext::Relinearize(const EvaluationKey & elk) const {
  return *this;
}
