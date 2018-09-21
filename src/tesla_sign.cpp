#include "tesla.h"
#include "sample.h"
#include "polyutil.h"

#include <cassert>
#include <NTL/ZZ_pX.h>

using namespace rlwe;
using namespace rlwe::tesla;

Signature tesla::Sign(const std::string & message, const SigningKey & signer) {
  const KeyParameters & params = signer.GetParameters();

  // Setup global coefficient modulus 
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Convert given a1, a2, e1, e2, s into polynomials under the global modulus
  ZZ_pX a1 = conv<ZZ_pX>(params.GetPolyConstants().a);
  ZZ_pX a2 = conv<ZZ_pX>(params.GetPolyConstants().b);
  ZZ_pX e1 = conv<ZZ_pX>(signer.GetErrorValues().a);
  ZZ_pX e2 = conv<ZZ_pX>(signer.GetErrorValues().b);
  ZZ_pX s = conv<ZZ_pX>(signer.GetSecret());

  // Sample y from R_{q,[B]}
  ZZ_pX y = conv<ZZ_pX>(UniformSample(params.GetPolyModulusDegree(), -params.GetB(), params.GetB() + 1));

  // v1 = a1 * y in R_q
  ZZ_pX v1_p;
  MulMod(v1_p, a1, y, params.GetPolyModulus());
  ZZX v1 = conv<ZZX>(v1_p);  

  // v2 = a2 * y in R_q
  ZZ_pX v2_p;
  MulMod(v2_p, a2, y, params.GetPolyModulus());
  ZZX v2 = conv<ZZX>(v2_p);

  // Round v1, v2 by applying [...]_{d,q}
  RoundCoeffsTESLA(v1, v1, params.GetLSBValue()); 
  RoundCoeffsTESLA(v2, v2, params.GetLSBValue()); 

  // c' = Hash(v1, v2, u)
  unsigned char c_prime[crypto_hash_sha256_BYTES];
  Hash(c_prime, v1, v2, message);
  ZZX c = Encode(c_prime, params);
  ZZ_pX c_p = conv<ZZ_pX>(c);

  // z = y + s * c
  ZZ_pX z_p; 
  MulMod(z_p, s, c_p, params.GetPolyModulus());
  z_p += y;

  // Convert z back into raw polynomial data 
  ZZX z = conv<ZZX>(z_p);
  CenterCoeffs(z, z, params.GetCoeffModulus());

  // Assert that z is in the ring R_{B - U}
  ZZ bound = params.GetB() - params.GetU();
  if (!IsInRange(z, -bound, bound)) {
    return Sign(message, signer); 
  }

  // w1, w2 need to fall within bound 2^d - L
  bound = params.GetLSBValue() - params.GetErrorBound();

  // w1 = v1 - e1 * c
  ZZ_pX w1_p(v1_p); 
  ZZ_pX buffer;
  MulMod(buffer, e1, c_p, params.GetPolyModulus());
  w1_p -= buffer;
  ZZX w1 = conv<ZZX>(w1_p);

  // d least significant bits in w1 are not small enough
  CenterCoeffs(w1, w1, params.GetLSBValue());
  if (!IsInRange(w1, -bound, bound)) {
    return Sign(message, signer);
  }

  // w2 = v2 - e2 * c
  ZZ_pX w2_p(v2_p);
  MulMod(buffer, e2, c_p, params.GetPolyModulus());
  w2_p -= buffer;
  ZZX w2 = conv<ZZX>(w2_p);

  // d least significant bits in w2 are not small enough
  CenterCoeffs(w2, w2, params.GetLSBValue());
  if (!IsInRange(w2, -bound, bound)) {
    return Sign(message, signer);
  }

  return Signature(z, c_prime, params);
}

bool tesla::Verify(const std::string & message, const Signature & sig, const VerificationKey & verif) {
  assert(sig.GetParameters() == verif.GetParameters());
  const KeyParameters & params = sig.GetParameters();

  // Setup global coefficient modulus 
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Extract polynomials serving as global constants
  ZZ_pX a1 = conv<ZZ_pX>(params.GetPolyConstants().a);
  ZZ_pX a2 = conv<ZZ_pX>(params.GetPolyConstants().b);

  // Extract polynomials from verification key 
  ZZ_pX t1 = conv<ZZ_pX>(verif.GetValues().a);
  ZZ_pX t2 = conv<ZZ_pX>(verif.GetValues().b);

  // Extract polynomials from the signing key
  ZZ_pX z = conv<ZZ_pX>(sig.GetValue());
  ZZ_pX c = conv<ZZ_pX>(Encode(sig.GetHash(), params));

  // Setup temporary buffer
  ZZ_pX buffer;

  // w1' = a1 * z - t1 * c
  ZZ_pX w1_prime_p;
  MulMod(w1_prime_p, a1, z, params.GetPolyModulus());
  MulMod(buffer, t1, c, params.GetPolyModulus());
  w1_prime_p -= buffer;
  ZZX w1_prime = conv<ZZX>(w1_prime_p);

  // w2' = a2 * z - t2 * c
  ZZ_pX w2_prime_p;
  MulMod(w2_prime_p, a2, z, params.GetPolyModulus());
  MulMod(buffer, t2, c, params.GetPolyModulus());
  w2_prime_p -= buffer;
  ZZX w2_prime = conv<ZZX>(w2_prime_p);
   
  // Round w1', w2' by applying [...]_{d,q}
  RoundCoeffsTESLA(w1_prime, w1_prime, params.GetLSBValue());
  RoundCoeffsTESLA(w2_prime, w2_prime, params.GetLSBValue());

  // c'' = Hash(w1', w2', message)
  unsigned char c_prime2[crypto_hash_sha256_BYTES];
  Hash(c_prime2, w1_prime, w2_prime, message);

  // Assert that c == c''
  for (int i = 0; i < crypto_hash_sha256_BYTES; i++) {
    if (sig.GetHash()[i] != c_prime2[i]) {
      return false;
    }
  }

  // Assert that z is in the ring R_{B - U} 
  ZZ bound = params.GetB() - params.GetU();
  return IsInRange(sig.GetValue(), -bound, bound);
}
