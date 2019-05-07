#define crypto_scalarmult_ed25519_BYTES 32U
#define crypto_scalarmult_ed25519_SCALARBYTES 32U

int crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                              const unsigned char *p);
int crypto_scalarmult_ed25519_noclamp(unsigned char *q, const unsigned char *n,
                                      const unsigned char *p);
int crypto_scalarmult_ed25519_base(unsigned char *q, const unsigned char *n);
int crypto_scalarmult_ed25519_base_noclamp(unsigned char *q, const unsigned char *n);