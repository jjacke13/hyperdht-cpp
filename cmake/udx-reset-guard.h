// A stream ID is not proof that an unrelated UDP endpoint may reset it.
// shortcut: source-spoofed resets remain possible, authenticate controls in a future wire revision.
static bool
hyperdht_udx_reset_source (udx_stream_t *stream, udx_socket_t *socket, const struct sockaddr *addr) {
  if (stream->socket != socket) return false;
  struct sockaddr_storage remote = stream->remote_addr;
  struct sockaddr_storage from = {0};
  if (addr->sa_family == AF_INET) memcpy(&from, addr, sizeof(struct sockaddr_in));
  else if (addr->sa_family == AF_INET6) memcpy(&from, addr, sizeof(struct sockaddr_in6));
  else return false;
  if (is_addr_v4_mapped((struct sockaddr *) &remote)) addr_to_v4((struct sockaddr_in6 *) &remote);
  if (is_addr_v4_mapped((struct sockaddr *) &from)) addr_to_v4((struct sockaddr_in6 *) &from);
  if (remote.ss_family != from.ss_family) return false;
  if (from.ss_family == AF_INET) {
    const struct sockaddr_in *a = (const struct sockaddr_in *) &remote;
    const struct sockaddr_in *b = (const struct sockaddr_in *) &from;
    return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
  }
  const struct sockaddr_in6 *a = (const struct sockaddr_in6 *) &remote;
  const struct sockaddr_in6 *b = (const struct sockaddr_in6 *) &from;
  return a->sin6_port == b->sin6_port && a->sin6_scope_id == b->sin6_scope_id &&
         memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0;
}
