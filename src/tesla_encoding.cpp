#include "tesla.h"

#include <sstream>

using namespace rlwe;
using namespace rlwe::tesla;

void tesla::Hash(unsigned char * output, const ZZX & p1, const ZZX & p2, const std::string & message) {
  // Concatenate everything into a single string
  std::stringstream ss;
  ss << p1 << p2 << message;

  // Convert stream into actual string
  std::string cc;
  ss >> cc;

  // Convert input into its c_string equivalent
  const unsigned char * input = reinterpret_cast<const unsigned char *>(cc.c_str());
  long inlen = cc.length();

  // Perform hash function and store the result 
  crypto_hash_sha256(output, input, inlen);
}

ZZX tesla::Encode(const unsigned char * hash_val) {
  // TODO: Implement encoding algorithm described in the paper    
}
