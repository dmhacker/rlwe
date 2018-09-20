#include "tesla.h"
#include "sampling.h"
#include "sha256.h"
#include "util.h"

#include <sstream>
#include <cassert>
#include <NTL/ZZ_pX.h>

using namespace rlwe;
using namespace rlwe::tesla;

std::string tesla::Hash(const ZZX & p1, const ZZX & p2, const std::string & message) {
  // Concatenate everything into a single string
  std::stringstream ss;
  ss << p1 << p2 << message;

  // Convert stream into actual string
  std::string result;
  ss >> result;

  // Return SHA-256 of concatenated string
  return sha256(result);
}

ZZX tesla::Encode(const std::string & hash_val) {
  
}

Signature tesla::Sign(const std::string & message, const SigningKey & signer) {
  const KeyParameters & params = signer.GetParameters();

  // Setup global coefficient modulus 
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Convert given a1, a2, e1, e2, s polynomials into polynomials under the global modulus
  ZZ_pX a1 = conv<ZZ_pX>(params.GetPolyConstants().a);
  ZZ_pX a2 = conv<ZZ_pX>(params.GetPolyConstants().b);
  ZZ_pX e1 = conv<ZZ_pX>(signer.GetErrorValues().a);
  ZZ_pX e2 = conv<ZZ_pX>(signer.GetErrorValues().b);
  ZZ_pX s = conv<ZZ_pX>(signer.GetSecret());

  // Sample y from R_{q,[B]}
  ZZ_pX y = conv<ZZ_pX>(UniformSample(params.GetPolyModulusDegree(), -params.GetB(), params.GetB() + 1));

  // v1 = a1 * y in R_q
  ZZ_pX v1_mod;
  MulMod(v1_mod, a1, y, params.GetPolyModulus());

  // v2 = a2 * y in R_q
  ZZ_pX v2_mod;
  MulMod(v2_mod, a2, y, params.GetPolyModulus());

  // Round v1, v2 coefficients by applying [...]_{d,q}
  ZZX v1 = conv<ZZX>(v1_mod);  
  ZZX v2 = conv<ZZX>(v2_mod);
  TeslaRoundCoeffs(v1, params.GetLSBValue()); 
  TeslaRoundCoeffs(v2, params.GetLSBValue()); 

  // c' = Hash(v1, v2, u)
  std::string c_prime = Hash(v1, v2, message);
  ZZX c = Encode(c_prime);
  ZZ_pX c_mod = conv<ZZ_pX>(c);

  // z = y + s * c
  ZZ_pX z_mod; 
  MulMod(z_mod, s, c_mod, params.GetPolyModulus());
  z_mod += y;

  // Convert z back into raw polynomial data 
  ZZX z = conv<ZZX>(z_mod);
  CenterCoeffs(z, params.GetCoeffModulus());

  // Assert that z is in the ring R_{B - U}
  if (!IsInRange(z, params.GetB() - params.GetU())) {
    return Sign(message, signer); 
  }

  // Set up some variables for computation
  ZZ_pX w1_mod(v1_mod); 
  ZZ_pX w2_mod(v2_mod);
  ZZ_pX buffer;

  // w1 = v1 - e1 * c
  MulMod(buffer, e1, c_mod, params.GetPolyModulus());
  w1_mod -= buffer;

  // w2 = v2 - e2 * c
  MulMod(buffer, e2, c_mod, params.GetPolyModulus());
  w2_mod -= buffer;

  // Convert w1, w2 back to raw polynomial forms
  ZZX w1 = conv<ZZX>(w1_mod);
  ZZX w2 = conv<ZZX>(w2_mod);

  // TODO: Final check to make sure w1 and w2 are in R_{2^d - L}

  return Signature(z, c_prime, params);
}

bool tesla::Verify(const std::string & message, const Signature & sig, const VerificationKey & verif) {
  assert(sig.GetParameters() == verif.GetParameters());
  const KeyParameters & params = sig.GetParameters();


}
