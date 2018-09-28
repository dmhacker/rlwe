#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/pair.h>

#define DEFAULT_POLY_MODULUS_DEGREE 1024
#define DEFAULT_COEFF_MODULUS 12289
#define DEFAULT_ERROR_STANDARD_DEVIATION 2.828f

#define SEED_BYTE_LENGTH 32
#define SHARED_KEY_BYTE_LENGTH 32

using namespace NTL;

namespace rlwe {
  namespace newhope {
    class KeyParameters;
    class Server;
    class Client;
    class Packet;

    /* Initialization procedures */
    void Initialize(Server & server);
    void Initialize(Client & client); 

    /* Object-oriented variants */
    Server CreateServer(const KeyParameters & params);
    Client CreateClient(const KeyParameters & params);

    /* Packet receiving/processing */
    void WritePacket(Packet & packet, const Server & server);
    void ReadPacket(Client & client, const Packet & packet);
    void WritePacket(Packet & packet, const Client & client);
    void ReadPacket(Server & server, const Packet & packet);

    /* Object-oriented variants */
    Packet CreatePacket(const Server & server);
    Packet CreatePacket(const Client & client);

    /* Util functions */
    void Parse(ZZX & a, size_t len, const ZZ & q, const uint8_t seed[SEED_BYTE_LENGTH]);
    size_t CompressPoly(uint8_t * output, size_t coeff_bit_length, const ZZX & poly);
    size_t DecompressPoly(ZZX & poly, size_t polylen, const uint8_t * output, size_t coeff_bit_length);
    void NHSEncode(ZZX & k, const uint8_t v[SHARED_KEY_BYTE_LENGTH], const ZZ & q);
    void NHSDecode(uint8_t v[SHARED_KEY_BYTE_LENGTH], const ZZX & k, const ZZ & q);
    void NHSCompress(ZZX & cc, const ZZX & c, const ZZ & q);
    void NHSDecompress(ZZX & c, const ZZX & cc, const ZZ & q);

    class KeyParameters {
      private:
        /* Given parameters */ 
        size_t n;
        ZZ q;
        float sigma;
        /* Calculated */
        ZZ_pXModulus phi;
        uint8_t ** pmat;
        size_t pmat_rows; 
      public:
        /* Constructors */
        KeyParameters();
        KeyParameters(size_t n, const ZZ & q); 
        KeyParameters(size_t n, const ZZ & q, float sigma);
        
        /* Destructors */
        ~KeyParameters() {
          for (size_t i = 0; i < pmat_rows; i++) {
            free(pmat[i]);
          }
          free(pmat);
        }

        /* Getters */
        const ZZ & GetCoeffModulus() const { return q; }
        size_t GetPolyModulusDegree() const { return n; }
        const ZZ_pXModulus & GetPolyModulus() const { return phi; }
        float GetErrorStandardDeviation() const { return sigma; }
        uint8_t ** GetProbabilityMatrix() const { return pmat; }
        size_t GetProbabilityMatrixRows() const { return pmat_rows; }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const KeyParameters& params) {
          return stream << "[n = " << params.n << ", q = " << params.q  << "]";
        }

        /* Equality */
        bool operator== (const KeyParameters & kp) const {
          return n == kp.n && q == kp.q && sigma == kp.sigma;
        }
    };

    class Server {
      private:
        ZZX s;
        ZZX b;
        uint8_t seed[SEED_BYTE_LENGTH];
        uint8_t shared[SHARED_KEY_BYTE_LENGTH];
        const KeyParameters & params;
      public:
        /* Constructors */
        Server(const KeyParameters & params) : params(params) {}

        /* Getters */
        const ZZX & GetSecretKey() const {
          return s;
        }
        const ZZX & GetPublicKey() const {
          return b;
        }
        const uint8_t * GetSeed() const {
          return seed;
        }
        const uint8_t * GetSharedKey() const {
          return shared;
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        void SetSecretKey(const ZZX & s) {
          this->s = s;
        }
        void SetPublicKey(const ZZX & b) {
          this->b = b;
        }
        void SetSeed(const uint8_t seed[SEED_BYTE_LENGTH]) {
          memcpy(this->seed, seed, SEED_BYTE_LENGTH);
        }
        void SetSharedKey(const uint8_t shared[SHARED_KEY_BYTE_LENGTH]) {
          memcpy(this->shared, shared, SHARED_KEY_BYTE_LENGTH);
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const Server & server) {
          return stream << 
            "{s = " << server.s << 
            ", b = " << server.b << 
            ", seed = " << server.seed << 
            "}";
        }
    };

    class Client {
      private:
        ZZX s;
        ZZX u;
        ZZX c;
        Pair<ZZX, ZZX> e;
        uint8_t shared[SHARED_KEY_BYTE_LENGTH];
        const KeyParameters & params;
      public:
        /* Constructors */
        Client(const KeyParameters & params) : params(params) {}

        /* Getters */
        const ZZX & GetSecretKey() const {
          return s;
        }
        const ZZX & GetPublicKey() const {
          return u;
        }
        const ZZX & GetCiphertext() const {
          return c;
        }
        const Pair<ZZX, ZZX> & GetErrors() const {
          return e;
        }
        const uint8_t * GetSharedKey() const {
          return shared;
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        void SetSecretKey(const ZZX & s) {
          this->s = s;
        }
        void SetPublicKey(const ZZX & u) {
          this->u = u;
        }
        void SetCiphertext(const ZZX & c) {
          this->c = c;
        }
        void SetErrors(const ZZX & e1, const ZZX & e2) {
          this->e.a = e1;
          this->e.b = e2;
        }
        void SetSharedKey(const uint8_t shared[SHARED_KEY_BYTE_LENGTH]) {
          memcpy(this->shared, shared, SHARED_KEY_BYTE_LENGTH);
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const Client & client) {
          return stream << 
            "{s = " << client.s << 
            ", u = " << client.u << 
            ", c  = " << client.c << 
            "}";
        }
    };

    /* Repesents a fixed, heap-allocated array of bytes */
    /* Unlike other classes here, the array is directly modifiable */
    class Packet {
      private:
        uint8_t * bytes;
        size_t len;
      public:
        Packet(size_t len) : len(len) {
          bytes = (uint8_t *) malloc(len);
        }

        ~Packet() {
          free(bytes);
        }

        size_t GetLength() const {
          return len;
        }

        uint8_t * GetBytes() const {
          return bytes;
        }
    };
  }
}
