#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/RR.h>
#include <NTL/pair.h>

using namespace NTL;

namespace rlwe {

  class Plaintext;
  class PublicKey;
  class PrivateKey;
  class EvaluationKey;

  class KeyParameters {
    private:
      /* Given parameters */ 
      long n;
      ZZ q;
      ZZ t;
      long log_w;
      float sigma;
      /* Calculated */
      ZZ_pXModulus phi;
      ZZ delta;
      RR downscale;
      ZZ w;
      ZZ w_mask;
      long l;
    public:
      /* Constructors */
      KeyParameters(long n, long q, long t) : KeyParameters(n, ZZ(q), ZZ(t)) {}
      KeyParameters(long n, ZZ q, ZZ t);
      KeyParameters(long n, ZZ q, ZZ t, long log_w, float sigma);

      /* Getters */
      ZZ GetCoeffModulus() const { return q; }
      ZZ GetPlainModulus() const { return t; }
      ZZ GetPlainToCoeffScalar() const { return delta; }
      RR GetCoeffToPlainScalar() const { return downscale; }
      long GetPolyModulusDegree() const { return n; }
      ZZ_pXModulus GetPolyModulus() const { return phi; }
      float GetErrorStandardDeviation() const { return sigma; }
      ZZ GetDecompositionBase() const { return w; }
      ZZ GetDecompositionBitMask() const { return w_mask; }
      long GetDecompositionBitCount() const { return log_w; }
      long GetDecompositionTermCount() const { return l; }

      /* Key generation */
      PrivateKey GeneratePrivateKey() const;
      PublicKey GeneratePublicKey(const PrivateKey & priv) const;
      PublicKey GeneratePublicKey(const PrivateKey & priv, const ZZX & a_random, const ZZX & e_random) const;
      EvaluationKey GenerateEvaluationKey(const PrivateKey & priv, long level) const;

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
        return n == kp.n && q == kp.q && t == kp.t && log_w == kp.log_w && sigma == kp.sigma && phi.val() == kp.phi.val();
      }
  };

  class Plaintext {
    private:
      ZZX m;
      const KeyParameters & params;
    public:
      /* Constructors */
      Plaintext(ZZX m, const KeyParameters & params) : m(m), params(params) {}

      /* Getters */
      const ZZX & GetMessage() const { 
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
      Ciphertext(ZZX c0, ZZX c1, const KeyParameters & params) : params(params) {
        c.SetLength(2);
        c[0] = c0;
        c[1] = c1;
      }
      Ciphertext(Vec<ZZX> c, const KeyParameters & params) : c(c), params(params) {}
      Ciphertext(const Ciphertext & ct) : c(ct.c), params(ct.params) {}

      /* Getters */
      const ZZX & operator[] (int index) const {
        return c[index]; 
      }
      long GetLength() const { 
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
      Pair<ZZX, ZZX> p;
      const KeyParameters & params;
    public:
      /* Constructors */
      PublicKey(ZZX p0, ZZX p1, const KeyParameters & params) : p(p0, p1), params(params) {}

      /* Getters */
      const Pair<ZZX, ZZX> & GetValues() const {
        return p;
      }
      const KeyParameters & GetParameters() const { 
        return params; 
      }

      /* Public key encryption */
      Ciphertext Encrypt(const Plaintext & plaintext) const; 

      /* Display to output stream */
      friend std::ostream& operator<< (std::ostream& stream, const PublicKey& pub) {
        return stream << pub.p;
      }
  };

  class PrivateKey {
    private:
      ZZX s;
      const KeyParameters & params;
    public:
      /* Constructors */
      PrivateKey(ZZX s, const KeyParameters & params) : s(s), params(params) {}

      /* Getters */
      ZZX GetSecret() const { 
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
      Vec<Pair<ZZX, ZZX>> r;
      long level;
      const KeyParameters & params;
    public:
      /* Constructors */
      EvaluationKey(Vec<Pair<ZZX, ZZX>> r, long level, const KeyParameters & params) : r(r), level(level), params(params) {}

      /* Getters */
      const Pair<ZZX, ZZX> & operator[] (int index) const {
        return r[index]; 
      }
      long GetLength() const { 
        return r.length(); 
      }
      long GetLevel() const {
        return level;
      }
      const KeyParameters & GetParameters() const { 
        return params; 
      }

      /* Display to output stream */
      friend std::ostream& operator<< (std::ostream& stream, const EvaluationKey & elk) {
        return stream << elk.r; 
      }  
  };
}
