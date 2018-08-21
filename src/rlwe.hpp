#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/RR.h>
#include <NTL/pair.h>

using namespace NTL;

namespace rlwe {

  namespace random {
    ZZX UniformSample(long degree, ZZ minimum_inclusive, ZZ maximum_exclusive);
    ZZX UniformSample(long degree, ZZ maximum_exclusive);
    ZZX GaussianSample(long degree, float standard_deviation); 
  }

  namespace util {
    void ScaleCoeffs(ZZX & poly, const RR scalar, const ZZ mod);
    void CenterCoeffs(ZZX & poly, const ZZ mod);
  }

  class Plaintext;
  class PublicKey;
  class PrivateKey;
  class EvaluationKey;

  const float ERROR_STANDARD_DEVIATION = 3.192f;
  const float EVAL_P_POWER = 3;
  const float EVAL_STANDARD_DEVIATION = std::pow(ERROR_STANDARD_DEVIATION, EVAL_P_POWER + 1);

  class KeyParameters {
    private:
      ZZ q;
      ZZ p;
      ZZ t;
      ZZ delta;
      RR downscale;
      long n;
      ZZ_pXModulus phi;
      float sigma;
      float sigma_t;
    public:
      /* Constructors */
      KeyParameters(long n0, long q0, long t0) : 
        KeyParameters(n0, ZZ(q0), ZZ(t0)) {}
      KeyParameters(long n0, ZZ q0, ZZ t0) : 
        KeyParameters(n0, q0, t0, 
            power(q0, EVAL_P_POWER), 
            ERROR_STANDARD_DEVIATION, 
            EVAL_STANDARD_DEVIATION) {}
      KeyParameters(long n0, ZZ q0, ZZ t0, ZZ p0, float sigma, float sigma_t);

      /* Getters */
      ZZ GetCoeffModulus() const { return q; }
      ZZ GetPlainModulus() const { return t; }
      ZZ GetPlainToCoeffScalar() const { return delta; }
      RR GetCoeffToPlainScalar() const { return downscale; }
      ZZ GetEvalModulus() const { return p; }
      long GetPolyModulusDegree() const { return n; }
      ZZ_pXModulus GetPolyModulus() const { return phi; }
      float GetErrorStandardDeviation() const { return sigma; }
      float GetEvalStandardDeviation() const { return sigma_t; }

      /* Key generation */
      PrivateKey GeneratePrivateKey() const;
      PublicKey GeneratePublicKey(const PrivateKey & priv) const;
      PublicKey GeneratePublicKey(const PrivateKey & priv, const ZZX & a_random, const ZZX & e_random) const;
      EvaluationKey GenerateEvaluationKey(const PrivateKey & priv) const;

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
      const ZZX & GetM() const { 
        return m; 
      }
      const KeyParameters & GetParameters() const { 
        return params; 
      }

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
      Vec<ZZX> c;
      const KeyParameters & params;
    public:
      /* Constructors */
      Ciphertext(ZZX c0, ZZX c1, const KeyParameters & params0) : params(params0) {
        c.SetLength(2);
        c[0] = c0;
        c[1] = c1;
      }
      Ciphertext(Vec<ZZX> c_vector, const KeyParameters & params0) : c(c_vector), params(params0) {}
      Ciphertext(const Ciphertext & ct) : c(ct.c), params(ct.params) {}

      /* Getters */
      const ZZX & operator[] (int index) const {
        return c[index]; 
      }
      long length() const { 
        return c.length(); 
      }
      const KeyParameters & GetParameters() const { 
        return params; 
      }

      /* Somewhat homomorphic encryption */
      Ciphertext & Negate();
      Ciphertext & operator+= (const Ciphertext & ct);
      Ciphertext & operator*= (const Ciphertext & ct);
      Ciphertext & Relinearize(const EvaluationKey & elk);

      /* Arithmetic overloading */
      friend Ciphertext operator- (const Ciphertext & ct) {
        Ciphertext result(ct);
        result.Negate();
        return result;
      }
      friend Ciphertext operator+ (const Ciphertext & ct1, const Ciphertext & ct2) {
        Ciphertext result(ct1); 
        result += ct2;
        return result;
      }
      friend Ciphertext operator* (const Ciphertext & ct1, const Ciphertext & ct2) {
        Ciphertext result(ct1);
        result *= ct2;
        return result;
      }

      /* Equality */
      bool operator== (const Ciphertext & ct) const {
        if (c.length() != ct.c.length() || !(params == ct.params)) {
          return false;
        }

        for (int i = 0; i < c.length(); i++) {
          if (c[i] != ct.c[i]) {
            return false;
          }
        }
        
        return true;
      }

      /* Display to output stream */
      friend std::ostream& operator<< (std::ostream& stream, const Ciphertext& ct) {
        return stream << ct.c;
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
      const ZZX & GetP0() const { 
        return p0; 
      }
      const ZZX & GetP1() const { 
        return p1; 
      } 
      const KeyParameters & GetParameters() const { 
        return params; 
      }

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
      ZZX GetS() const { 
        return s; 
      }
      const KeyParameters & GetParameters() const { 
        return params; 
      }

      /* Private key decryption */
      Plaintext Decrypt(const Ciphertext & ciphertext) const;

      /* Display to output stream */
      friend std::ostream& operator<< (std::ostream& stream, const PrivateKey& priv) {
        return stream << priv.s;
      }
  };

  class EvaluationKey {
    private:
      ZZX r0;
      ZZX r1;
      const KeyParameters & params;
    public:
      /* Constructors */
      EvaluationKey(ZZX r0_0, ZZX r1_0, const KeyParameters & params0) : r0(r0_0), r1(r1_0), params(params0) {}

      /* Getters */
      const ZZX & operator[] (int index) const {
        return index % 2 ? r1 : r0; 
      }
      const KeyParameters & GetParameters() const { 
        return params; 
      }

      /* Display to output stream */
      friend std::ostream& operator<< (std::ostream& stream, const EvaluationKey & elk) {
        return stream << elk.r0 << ", " << elk.r1;
      }  
  };
}
