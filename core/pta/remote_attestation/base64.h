#ifndef PTA_REMOTE_ATTESTATION_BASE64_H
#define PTA_REMOTE_ATTESTATION_BASE64_H

#include <stddef.h>
#include <stdint.h>

size_t base64_enc_len(size_t size);

int base64_encode(const unsigned char *in, unsigned long inlen, char *out,
                  unsigned long *outlen);

#endif /*PTA_REMOTE_ATTESTATION_BASE64_H*/
