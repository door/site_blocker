
void rawtcp_send(int sock,
                 const lenval_t *text,
                 const struct sockaddr_in *src,
                 const struct sockaddr_in *dst,
                 uint32_t seq, uint32_t ack, uint8_t flags);


int rawtcp_open();
