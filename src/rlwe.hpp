#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

using namespace NTL;

namespace rlwe {

  namespace random {
    ZZX UniformSample(long degree, ZZ field_modulus, bool flip_bits);
    ZZX GaussianSample(long degree); 
  }

  class PublicKey;
  class PrivateKey;

  class KeyParameters {
    private:
      long n;
      ZZ q;
      ZZ t;
      ZZ q_div_t;
      ZZ_pXModulus phi;
    public:
      /* Constructors */
      KeyParameters(long n0, ZZ q0, ZZ t0);

      /* Getters */
      ZZ GetCoeffModulus() const { return q; }
      ZZ GetPlainModulus() const { return t; }
      ZZ GetPlainToCoeffScalar() const { return q_div_t; }
      ZZ_pXModulus GetPolyModulus() const { return phi; }
      long GetPolyModulusDegree() const { return n; }

      /* Key generation */
      PrivateKey GeneratePrivateKey() const;
      PublicKey GeneratePublicKey(const PrivateKey & priv) const;

      /* Encoding and decoding */
      ZZX EncodeInteger(const ZZ & plaintext) const;
      ZZ DecodeInteger(const ZZX & encoding) const;

      /* Display to output stream */
      friend std::ostream& operator<< (std::ostream& stream, const KeyParameters& params) {
        return stream << "n = " << params.n << ", q = " << params.q << ", t = " << params.t;
      }
  };

  class Ciphertext {
    private:
      ZZX c0;
      ZZX c1;
    public:
      /* Constructors */
      Ciphertext(ZZX c0_0, ZZX c1_0) : c0(c0_0), c1(c1_0) {}

      /* Getters */
      ZZX GetC0() const { return c0; }
      ZZX GetC1() const { return c1; }

      /* Display to output stream */
      friend std::ostream& operator<< (std::ostream& stream, const Ciphertext& ct) {
        return stream << ct.c0 << ", " << ct.c1;
      }
  };

  class PublicKey {
    private:
      ZZX p0;
      ZZX p1;
      const KeyParameters & params;
    public:
      /* Constructors */
      PublicKey(ZZX p0_0, ZZX p1_0, const KeyParameters & params0) : p0(p0_0), p1(p1_0), params(params0) {}

      /* Getters */
      ZZX GetP0() const { return p0; }
      ZZX GetP1() const { return p1; } 

      /* Public key encryption */
      Ciphertext Encrypt(const ZZX & plaintext) const; 

      /* Display to output stream */
      friend std::ostream& operator<< (std::ostream& stream, const PublicKey& pub) {
        return stream << pub.p0 << ", " << pub.p1;
      }
  };

  class PrivateKey {
    private:
      ZZX s;
      const KeyParameters & params;
    public:
      /* Constructors */
      PrivateKey(ZZX s0, const KeyParameters & params0) : s(s0), params(params0) {}

      /* Getters */
      ZZX GetS() const { return s; }

      /* Private key decryption */
      ZZX Decrypt(const Ciphertext & ciphertext) const;

      /* Display to output stream */
      friend std::ostream& operator<< (std::ostream& stream, const PrivateKey& priv) {
        return stream << priv.s;
      }
  };
}
