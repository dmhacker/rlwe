#include "catch.hpp"
#include "newhope.h"

using namespace rlwe;
using namespace rlwe::newhope;

TEST_CASE("NewHope-Simple full key exchange") {
  KeyParameters params;

  Server server = CreateServer(params);
  Client client = CreateClient(params);

  Packet clientbound_packet = CreatePacket(server);
  ReadPacket(client, clientbound_packet);
  Packet serverbound_packet = CreatePacket(client);
  ReadPacket(server, serverbound_packet);

  for (size_t i = 0; i < SHARED_KEY_BYTE_LENGTH; i++) {
    REQUIRE(client.GetSharedKey()[i] == server.GetSharedKey()[i]);
  }
}
