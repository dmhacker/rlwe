#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/pair.h>

using namespace NTL;

namespace rlwe {

  namespace random {
    ZZX UniformSample(long degree, ZZ minimum_inclusive, ZZ maximum_exclusive);
    ZZX UniformSample(long degree, ZZ maximum_exclusive);
    ZZX GaussianSample(long degree, float standard_deviation); 
  }

  class Plaintext;
  class PublicKey;
  class PrivateKey;
  class RelinearizationKey;

  const float ERROR_STANDARD_DEVIATION = 3.192f;

  class KeyParameters {
    private:
      long n;
      float sigma;
      ZZ q;
      ZZ t;
      ZZ delta;
      ZZ T;
      ZZ_pXModulus phi;
    public:
      /* Constructors */
      KeyParameters(long n0, long q0, long t0) : KeyParameters(n0, ZZ(q0), ZZ(t0)) {}
      KeyParameters(long n0, ZZ q0, ZZ t0) : KeyParameters(n0, q0, t0, ERROR_STANDARD_DEVIATION, SqrRoot(q0)) {}
      KeyParameters(long n0, ZZ q0, ZZ t0, float sigma0, ZZ T0);

      /* Getters */
      ZZ GetCoeffModulus() const { return q; }
      ZZ GetPlainModulus() const { return t; }
      ZZ GetDeltaScalar() const { return delta; }
      ZZ_pXModulus GetPolyModulus() const { return phi; }
        ZZ GetRelinearizationBase() const { return T; }
        long GetPolyModulusDegree() const { return n; }
        float GetErrorStandardDeviation() const { return sigma; }

        /* Key generation */
        PrivateKey GeneratePrivateKey() const;
        PublicKey GeneratePublicKey(const PrivateKey & priv) const;
        RelinearizationKey GenerateEvaluationKey(const PrivateKey & priv) const;

        /* Encoding and decoding */
        Plaintext EncodeInteger(const ZZ & integer) const;
        Plaintext EncodeInteger(long integer) const;
        ZZ DecodeInteger(const Plaintext & plaintext) const;

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const KeyParameters& params) {
          return stream << "n = " << params.n << ", q = " << params.q << ", t = " << params.t;
        }

        /* Equality */
        bool operator== (const KeyParameters & kp) const {
          return n == kp.n && q == kp.q && t == kp.t && phi.val() == kp.phi.val();
        }
    };
    
    class Plaintext {
      private:
        ZZX m;
        const KeyParameters & params;
      public:
        /* Constructors */
        Plaintext(ZZX m0, const KeyParameters & params0) : m(m0), params(params0) {}

        /* Getters */
        ZZX GetM() const { return m; }

        /* Equality */
        bool operator== (const Plaintext & pt) const {
          return m == pt.m && params == pt.params;
        }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const Plaintext& pt) {
          return stream << pt.m; 
        }
    };

    class Ciphertext {
      private:
        ZZX c0;
        ZZX c1;
        const KeyParameters & params;
      public:
        /* Constructors */
        Ciphertext(ZZX c0_0, ZZX c1_0, const KeyParameters & params0) : c0(c0_0), c1(c1_0), params(params0) {}

        /* Getters */
        ZZX GetC0() const { return c0; }
        ZZX GetC1() const { return c1; }

        /* FV homomorphic encryption */
        Ciphertext Add(const Ciphertext & ct) const;
        Ciphertext Multiply(const Ciphertext & ct, const RelinearizationKey & rlk) const;

        /* Equality */
        bool operator== (const Ciphertext & ct) const {
          return c0 == ct.c0 && c1 == ct.c1 && params == ct.params;
        }

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
        Ciphertext Encrypt(const Plaintext & plaintext) const; 

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
        Plaintext Decrypt(const Ciphertext & ciphertext) const;

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const PrivateKey& priv) {
          return stream << priv.s;
        }
    };

    class RelinearizationKey {
      private:
        Vec<ZZX> r0s;
        Vec<ZZX> r1s;
        const KeyParameters & params;
      public:
        /* Constructors */
        RelinearizationKey(Vec<ZZX> r0_vector, Vec<ZZX> r1_vector, const KeyParameters & params0) : r0s(r0_vector), r1s(r1_vector), params(params0) {}

        /* Getters */
        const Vec<ZZX> & GetR0Vector() const { return r0s; }
        const Vec<ZZX> & GetR1Vector() const { return r1s; }

        /* Array accessor */
        Pair<ZZX, ZZX> operator[] (int index) const {
          Pair<ZZX, ZZX> pairing(r0s[index], r1s[index]);
          return pairing;
        }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const RelinearizationKey & rlk) {
          return stream << rlk.r0s << ", " << rlk.r1s; 
        }  
    };
}
