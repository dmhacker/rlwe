#include "catch.hpp"
#include "newhope.h"

using namespace rlwe;
using namespace rlwe::newhope;

TEST_CASE("") {
  KeyParameters params;

  Server server = CreateServer(params);
  Client client = CreateClient(params);

  uint8_t * clientbound_packet = CreatePacket(server);
  ReadPacket(client, clientbound_packet);
  uint8_t * serverbound_packet = CreatePacket(client);
  ReadPacket(server, serverbound_packet);

  free(clientbound_packet);
  free(serverbound_packet);

  REQUIRE(true);
}
