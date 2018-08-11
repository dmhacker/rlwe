#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

using namespace NTL;

namespace rlwe {
  class PublicKey;
  class PrivateKey;

  class KeyParameters {
    private:
      long n;
      ZZ q;
      ZZ t;
      ZZ_pXModulus phi;
    public:
      /* Constructors */
      KeyParameters(long n0, ZZ q0, ZZ t0);

      /* Getters */
      ZZ GetCoeffModulus() const { return q; }
      ZZ GetPlainModulus() const { return t; }
      ZZ_pXModulus GetPolyModulus() const { return phi; }
      long GetPolyModulusDegree() const { return n; }

      /* Key generation */
      PrivateKey GeneratePrivateKey() const;
      PublicKey GeneratePublicKey(const PrivateKey & priv) const;
  };

  class Ciphertext {
    private:
      ZZX c1;
      ZZX c2;
    public:
      /* Constructors */
      Ciphertext(ZZX c1_0, ZZX c2_0) : c1(c1_0), c2(c2_0) {}

      /* Getters */
      ZZX GetC1() const { return c1; }
      ZZX GetC2() const { return c2; }
  };

  class PublicKey {
    private:
      ZZX a;
      ZZX b;
      const KeyParameters & params;
    public:
      /* Constructors */
      PublicKey(ZZX a0, ZZX b0, const KeyParameters & p0) : a(a0), b(b0), params(p0) {}

      /* Getters */
      ZZX GetA() const { return a; }
      ZZX GetB() const { return b; } 

      /* Public key encryption */
      Ciphertext Encrypt(ZZX plaintext); 
  };

  class PrivateKey {
    private:
      ZZX e;
      ZZX s;
      const KeyParameters & params;
    public:
      /* Constructors */
      PrivateKey(ZZX e0, ZZX s0, const KeyParameters & p0) : e(e0), s(s0), params(p0) {}

      /* Getters */
      ZZX GetE() const { return e; }
      ZZX GetS() const { return s; }

      /* Private key decryption */
      ZZX Decrypt(Ciphertext ciphertext);
  };
}
