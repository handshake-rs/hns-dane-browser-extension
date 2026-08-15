#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WALLET_BOOTSTRAP_FD 3
#define WALLET_MAX_FRAME_BYTES 1048576U
#define WALLET_BOOTSTRAP_MAX_BYTES 256U

static const char SERVICE_SESSION_ID[] =
    "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo";

static char frame[WALLET_MAX_FRAME_BYTES + 1U];
static char response[8192];
static char bootstrap_network[16];
static char bootstrap_namespace_hex[33];
static char bootstrap_namespace_json[128];
static uint64_t bootstrap_network_magic;
static uint64_t bootstrap_namespace_generation;
static unsigned int bootstrap_namespace_first_byte;

static int read_exact(int descriptor, void *output, size_t length) {
  unsigned char *cursor = output;
  while (length > 0U) {
    ssize_t count = read(descriptor, cursor, length);
    if (count > 0) {
      cursor += (size_t)count;
      length -= (size_t)count;
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    return -1;
  }
  return 0;
}

static int write_exact(int descriptor, const void *input, size_t length) {
  const unsigned char *cursor = input;
  while (length > 0U) {
    ssize_t count = write(descriptor, cursor, length);
    if (count > 0) {
      cursor += (size_t)count;
      length -= (size_t)count;
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    return -1;
  }
  return 0;
}

static int receive_bootstrap(void) {
  struct stat bootstrap_status;
  struct stat stdin_status;
  unsigned char received[WALLET_BOOTSTRAP_MAX_BYTES + 1U];
  char canonical[WALLET_BOOTSTRAP_MAX_BYTES + 1U];
  size_t length = 0U;
  int canonical_length;
  size_t byte_index;
  size_t json_offset = 0U;

  if (fstat(WALLET_BOOTSTRAP_FD, &bootstrap_status) != 0 ||
      fstat(STDIN_FILENO, &stdin_status) != 0 ||
      !S_ISFIFO(bootstrap_status.st_mode) ||
      (bootstrap_status.st_dev == stdin_status.st_dev &&
       bootstrap_status.st_ino == stdin_status.st_ino)) {
    return -1;
  }

  for (;;) {
    ssize_t count = read(WALLET_BOOTSTRAP_FD, received + length,
                         WALLET_BOOTSTRAP_MAX_BYTES - length);
    if (count > 0) {
      length += (size_t)count;
      if (length == WALLET_BOOTSTRAP_MAX_BYTES) {
        return -1;
      }
      continue;
    }
    if (count == 0) {
      break;
    }
    if (errno != EINTR) {
      return -1;
    }
  }

  received[length] = '\0';
  if (sscanf((const char *)received,
             "chromium-wallet-read-bootstrap-v2\n%15[^\n]\n%" SCNu64
             "\n%32[0-9a-f]\n%" SCNu64 "\n",
             bootstrap_network, &bootstrap_network_magic,
             bootstrap_namespace_hex, &bootstrap_namespace_generation) != 4 ||
      strcmp(bootstrap_network, "regtest") != 0 ||
      bootstrap_network_magic != UINT64_C(2922943951) ||
      strlen(bootstrap_namespace_hex) != 32U ||
      bootstrap_namespace_generation == 0U) {
    return -1;
  }
  canonical_length = snprintf(
      canonical, sizeof(canonical),
      "chromium-wallet-read-bootstrap-v2\n%s\n%" PRIu64 "\n%s\n%" PRIu64
      "\n",
      bootstrap_network, bootstrap_network_magic, bootstrap_namespace_hex,
      bootstrap_namespace_generation);
  if (canonical_length < 0 || (size_t)canonical_length != length ||
      memcmp(received, canonical, length) != 0) {
    return -1;
  }
  bootstrap_namespace_json[json_offset++] = '[';
  for (byte_index = 0U; byte_index < 16U; ++byte_index) {
    unsigned int byte;
    int written;
    if (sscanf(&bootstrap_namespace_hex[byte_index * 2U], "%2x", &byte) != 1) {
      return -1;
    }
    if (byte_index == 0U) {
      bootstrap_namespace_first_byte = byte;
    }
    written = snprintf(bootstrap_namespace_json + json_offset,
                       sizeof(bootstrap_namespace_json) - json_offset,
                       byte_index == 0U ? "%u" : ",%u", byte);
    if (written < 0 ||
        (size_t)written >= sizeof(bootstrap_namespace_json) - json_offset) {
      return -1;
    }
    json_offset += (size_t)written;
  }
  if (json_offset + 2U > sizeof(bootstrap_namespace_json)) {
    return -1;
  }
  bootstrap_namespace_json[json_offset++] = ']';
  bootstrap_namespace_json[json_offset] = '\0';
  return close(WALLET_BOOTSTRAP_FD);
}

static int read_frame(void) {
  unsigned char prefix[4];
  uint32_t length;

  if (read_exact(STDIN_FILENO, prefix, sizeof(prefix)) != 0) {
    return -1;
  }
  length = ((uint32_t)prefix[0] << 24U) | ((uint32_t)prefix[1] << 16U) |
           ((uint32_t)prefix[2] << 8U) | (uint32_t)prefix[3];
  if (length == 0U || length > WALLET_MAX_FRAME_BYTES ||
      read_exact(STDIN_FILENO, frame, length) != 0) {
    return -1;
  }
  frame[length] = '\0';
  return 0;
}

static int write_frame(const char *payload) {
  size_t length = strlen(payload);
  unsigned char prefix[4];

  if (length == 0U || length > WALLET_MAX_FRAME_BYTES) {
    return -1;
  }
  prefix[0] = (unsigned char)(length >> 24U);
  prefix[1] = (unsigned char)(length >> 16U);
  prefix[2] = (unsigned char)(length >> 8U);
  prefix[3] = (unsigned char)length;
  return write_exact(STDOUT_FILENO, prefix, sizeof(prefix)) == 0 &&
                 write_exact(STDOUT_FILENO, payload, length) == 0
             ? 0
             : -1;
}

static int extract_string(const char *json, const char *field, char *output,
                          size_t output_size) {
  char marker[96];
  const char *start;
  const char *end;
  size_t length;

  if (snprintf(marker, sizeof(marker), "\"%s\":\"", field) < 0) {
    return -1;
  }
  start = strstr(json, marker);
  if (start == NULL) {
    return -1;
  }
  start += strlen(marker);
  end = strchr(start, '"');
  if (end == NULL) {
    return -1;
  }
  length = (size_t)(end - start);
  if (length == 0U || length >= output_size) {
    return -1;
  }
  memcpy(output, start, length);
  output[length] = '\0';
  return 0;
}

static int extract_u64(const char *json, const char *field, uint64_t *output) {
  char marker[96];
  const char *start;
  char *end;
  unsigned long long value;

  if (snprintf(marker, sizeof(marker), "\"%s\":", field) < 0) {
    return -1;
  }
  start = strstr(json, marker);
  if (start == NULL) {
    return -1;
  }
  start += strlen(marker);
  errno = 0;
  value = strtoull(start, &end, 10);
  if (errno != 0 || end == start) {
    return -1;
  }
  *output = (uint64_t)value;
  return 0;
}

static int contains_exact_string(const char *json, const char *field,
                                 const char *value) {
  char expected[256];
  int length = snprintf(expected, sizeof(expected), "\"%s\":\"%s\"", field,
                        value);
  return length > 0 && (size_t)length < sizeof(expected) &&
         strstr(json, expected) != NULL;
}

static size_t count_occurrences(const char *value, const char *needle) {
  size_t count = 0U;
  size_t needle_length = strlen(needle);
  while ((value = strstr(value, needle)) != NULL) {
    ++count;
    value += needle_length;
  }
  return count;
}

static int serve_wallet_authority(const char *host_session,
                                  uint64_t restart_generation,
                                  uint64_t channel_sequence,
                                  uint64_t wallet_authority_revision) {
  uint64_t request_generation;
  uint64_t request_sequence;
  uint64_t request_network_magic;
  uint64_t request_namespace_generation;
  char namespace_field[192];
  char request_id[64];
  uint64_t response_network_magic = bootstrap_network_magic;

  if (bootstrap_namespace_first_byte == 7U && channel_sequence == 9U) {
    ++response_network_magic;
  }
  if (bootstrap_namespace_first_byte == 8U && channel_sequence == 12U) {
    ++wallet_authority_revision;
  }

  if (snprintf(namespace_field, sizeof(namespace_field),
               "\"namespaceId\":%s", bootstrap_namespace_json) < 0 ||
      read_frame() != 0 ||
      strstr(frame, "\"frameType\":\"request\"") == NULL ||
      strstr(frame, "\"protocolVersion\":2") == NULL ||
      !contains_exact_string(frame, "hostSessionId", host_session) ||
      !contains_exact_string(frame, "serviceSessionId", SERVICE_SESSION_ID) ||
      extract_u64(frame, "restartGeneration", &request_generation) != 0 ||
      request_generation != restart_generation ||
      extract_u64(frame, "channelSequence", &request_sequence) != 0 ||
      request_sequence != channel_sequence ||
      extract_string(frame, "requestId", request_id, sizeof(request_id)) != 0 ||
      strlen(request_id) != 22U ||
      count_occurrences(frame, "\"operation\":") != 2U ||
      strstr(frame, "\"operation\":\"walletAuthority\"") == NULL ||
      strstr(frame, "\"operation\":\"currentHnsContext\"") == NULL ||
      !contains_exact_string(frame, "network", bootstrap_network) ||
      extract_u64(frame, "networkMagic", &request_network_magic) != 0 ||
      request_network_magic != bootstrap_network_magic ||
      strstr(frame, namespace_field) == NULL ||
      extract_u64(frame, "namespaceLeaseGeneration",
                  &request_namespace_generation) != 0 ||
      request_namespace_generation != bootstrap_namespace_generation ||
      !contains_exact_string(frame, "module", "handshake")) {
    return -1;
  }

  if (snprintf(
          response, sizeof(response),
          "{\"frameType\":\"response\",\"envelope\":{"
          "\"protocolVersion\":2,\"hostSessionId\":\"%s\","
          "\"serviceSessionId\":\"%s\",\"restartGeneration\":%" PRIu64 ","
          "\"channelSequence\":%" PRIu64 ",\"requestId\":\"%s\",\"body\":{"
          "\"result\":\"walletAuthority\",\"context\":{"
          "\"network\":\"%s\",\"networkMagic\":%" PRIu64 ","
          "\"namespaceId\":%s,\"namespaceLeaseGeneration\":%" PRIu64 ","
          "\"activeWallet\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"
          "\"account\":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"
          "\"walletAuthorityRevision\":%" PRIu64 ","
          "\"accountAuthorityRevision\":9007199254740995,"
          "\"locked\":false,\"module\":\"handshake\","
          "\"persistentWalletConfirmed\":true,\"recoveryPending\":false,"
          "\"retirementPending\":false,\"hnsReadsReady\":true}}}}",
          host_session, SERVICE_SESSION_ID, restart_generation, channel_sequence,
          request_id, bootstrap_network, response_network_magic,
          bootstrap_namespace_json, bootstrap_namespace_generation,
          wallet_authority_revision) < 0 ||
      write_frame(response) != 0) {
    return -1;
  }
  return 0;
}

static int serve_wallet_reads(void) {
  static const char *operations[] = {"status",          "listAccounts",
                                     "balance",         "receiveTarget",
                                     "transactionHistory", "moduleStatus",
                                     "status",          "listAccounts",
                                     "status",          "listAccounts"};
  static const char *bodies[] = {
      "{\"result\":\"status\",\"status\":{\"locked\":false,"
      "\"activeWallet\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"
      "\"enabledModules\":[\"handshake\"],"
      "\"mainnetSettlementEnabled\":false}}",
      "{\"result\":\"accounts\",\"accounts\":[{"
      "\"accountId\":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"
      "\"module\":\"handshake\",\"label\":\"Fixture HNS\","
      "\"receiveDisplay\":null}]}",
      "{\"result\":\"balance\",\"amount\":{\"asset\":\"HNS\","
      "\"base_units\":\"42\"}}",
      "{\"result\":\"receiveTarget\",\"target\":{"
      "\"module\":\"handshake\","
      "\"account\":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"
      "\"display\":\"rs1qsealedfixture\",\"derivation_index\":3}}",
      "{\"result\":\"transactionHistory\",\"transactions\":[]}",
      "{\"result\":\"moduleStatus\",\"status\":{\"phase\":\"ready\","
      "\"validated_height\":144,\"scanned_height\":144,"
      "\"target_height\":144,\"last_error\":null}}",
      "{\"result\":\"status\",\"status\":{\"locked\":false,"
      "\"activeWallet\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"
      "\"enabledModules\":[\"handshake\"],"
      "\"mainnetSettlementEnabled\":false}}",
      "{\"result\":\"accounts\",\"accounts\":[{"
      "\"accountId\":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"
      "\"module\":\"handshake\",\"label\":\"Fixture HNS\","
      "\"receiveDisplay\":null}]}",
      "{\"result\":\"status\",\"status\":{\"locked\":false,"
      "\"activeWallet\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],"
      "\"enabledModules\":[\"handshake\"],"
      "\"mainnetSettlementEnabled\":false}}",
      "{\"result\":\"accounts\",\"accounts\":[{"
      "\"accountId\":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"
      "\"module\":\"handshake\",\"label\":\"Fixture HNS\","
      "\"receiveDisplay\":null}]}"};
  static const char account[] =
      "\"account\":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9]";
  char host_session[64];
  char request_id[64];
  uint64_t restart_generation;
  size_t index;

  if (read_frame() != 0 ||
      strstr(frame, "\"frameType\":\"hello\"") == NULL ||
      strstr(frame, "\"protocolVersion\":2") == NULL ||
      !contains_exact_string(frame, "platform", "chromiumNativeHost") ||
      extract_string(frame, "hostSessionId", host_session,
                     sizeof(host_session)) != 0 ||
      strlen(host_session) != 43U ||
      extract_u64(frame, "restartGeneration", &restart_generation) != 0 ||
      restart_generation == 0U) {
    return -1;
  }

  if (snprintf(
          response, sizeof(response),
          "{\"frameType\":\"hello\",\"hello\":{\"protocolVersion\":2,"
          "\"platform\":\"chromiumNativeHost\",\"hostSessionId\":\"%s\","
          "\"serviceSessionId\":\"%s\",\"restartGeneration\":%" PRIu64 ","
          "\"capabilities\":[\"canonicalFraming\",\"restartIsolation\","
          "\"opaqueAuthorityRegistry\",\"structuredApprovals\",\"typedEvents\","
          "\"walletOperations\",\"hnsReadOperationsV1\","
          "\"hnsWalletAuthorityContextV1\"],\"limits\":{"
          "\"outerFrameBytes\":1048576,\"providerRequestBytes\":65536,"
          "\"providerResultBytes\":262144,\"providerEventBytes\":65536,"
          "\"approvalFrameBytes\":16384,\"approvalLifetimeMs\":90000}}}",
          host_session, SERVICE_SESSION_ID, restart_generation) < 0 ||
      write_frame(response) != 0) {
    return -1;
  }

  for (index = 0U; index < 8U; ++index) {
    char operation[64];
    uint64_t request_generation;
    uint64_t channel_sequence;

    if (read_frame() != 0 ||
        strstr(frame, "\"frameType\":\"request\"") == NULL ||
        strstr(frame, "\"protocolVersion\":2") == NULL ||
        !contains_exact_string(frame, "hostSessionId", host_session) ||
        !contains_exact_string(frame, "serviceSessionId", SERVICE_SESSION_ID) ||
        extract_u64(frame, "restartGeneration", &request_generation) != 0 ||
        request_generation != restart_generation ||
        extract_u64(frame, "channelSequence", &channel_sequence) != 0 ||
        channel_sequence != index + 1U ||
        extract_string(frame, "requestId", request_id, sizeof(request_id)) != 0 ||
        strlen(request_id) != 22U ||
        count_occurrences(frame, "\"operation\":") != 2U ||
        snprintf(operation, sizeof(operation), "\"operation\":\"%s\"",
                 operations[index]) < 0 ||
        strstr(frame, operation) == NULL || strstr(frame, "workflow") != NULL ||
        strstr(frame, "valueMovement") != NULL ||
        (index >= 2U && index <= 5U &&
         !contains_exact_string(frame, "module", "handshake")) ||
        (index >= 2U && index <= 4U && strstr(frame, account) == NULL)) {
      return -1;
    }

    if (snprintf(
            response, sizeof(response),
            "{\"frameType\":\"response\",\"envelope\":{"
            "\"protocolVersion\":2,\"hostSessionId\":\"%s\","
            "\"serviceSessionId\":\"%s\",\"restartGeneration\":%" PRIu64 ","
            "\"channelSequence\":%zu,\"requestId\":\"%s\",\"body\":{"
            "\"result\":\"wallet\",\"response\":%s}}}",
            host_session, SERVICE_SESSION_ID, restart_generation, index + 1U,
            request_id, bodies[index]) < 0 ||
        write_frame(response) != 0) {
      return -1;
    }
  }

  if (serve_wallet_authority(host_session, restart_generation, 9U,
                             UINT64_C(9007199254740993)) != 0) {
    return -1;
  }

  for (index = 8U; index < sizeof(operations) / sizeof(operations[0]); ++index) {
    char operation[64];
    uint64_t request_generation;
    uint64_t channel_sequence;
    uint64_t expected_sequence = index + 2U;

    if (read_frame() != 0 ||
        strstr(frame, "\"frameType\":\"request\"") == NULL ||
        strstr(frame, "\"protocolVersion\":2") == NULL ||
        !contains_exact_string(frame, "hostSessionId", host_session) ||
        !contains_exact_string(frame, "serviceSessionId", SERVICE_SESSION_ID) ||
        extract_u64(frame, "restartGeneration", &request_generation) != 0 ||
        request_generation != restart_generation ||
        extract_u64(frame, "channelSequence", &channel_sequence) != 0 ||
        channel_sequence != expected_sequence ||
        extract_string(frame, "requestId", request_id, sizeof(request_id)) != 0 ||
        strlen(request_id) != 22U ||
        count_occurrences(frame, "\"operation\":") != 2U ||
        snprintf(operation, sizeof(operation), "\"operation\":\"%s\"",
                 operations[index]) < 0 ||
        strstr(frame, operation) == NULL || strstr(frame, "workflow") != NULL ||
        strstr(frame, "valueMovement") != NULL) {
      return -1;
    }
    if (snprintf(
            response, sizeof(response),
            "{\"frameType\":\"response\",\"envelope\":{"
            "\"protocolVersion\":2,\"hostSessionId\":\"%s\","
            "\"serviceSessionId\":\"%s\",\"restartGeneration\":%" PRIu64 ","
            "\"channelSequence\":%" PRIu64 ",\"requestId\":\"%s\",\"body\":{"
            "\"result\":\"wallet\",\"response\":%s}}}",
            host_session, SERVICE_SESSION_ID, restart_generation,
            expected_sequence, request_id, bodies[index]) < 0 ||
        write_frame(response) != 0) {
      return -1;
    }
  }

  if (serve_wallet_authority(host_session, restart_generation, 12U,
                             UINT64_C(9007199254740993)) != 0) {
    return -1;
  }

  for (;;) {
    pause();
  }
}

int main(int argc, char **argv) {
  struct stat database_status;
  int database_descriptor;

  if (argc != 3 || strcmp(argv[1], "--database") != 0 || argv[2][0] != '/') {
    return 90;
  }
  database_descriptor = open(argv[2], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (database_descriptor < 0 || fstat(database_descriptor, &database_status) != 0 ||
      !S_ISREG(database_status.st_mode)) {
    return 91;
  }
  if (receive_bootstrap() != 0) {
    return 92;
  }
  return serve_wallet_reads() == 0 ? 0 : 93;
}
