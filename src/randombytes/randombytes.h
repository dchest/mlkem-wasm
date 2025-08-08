#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stdint.h>
#include <stdlib.h>

void randombytes_reset(void);
void randombytes(uint8_t *buf, size_t n);

#endif /* !RANDOMBYTES_H */
