#ifndef __BASE64_H__
#define __BASE64_H__

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint32_t base64_encode(const uint8_t *hexdata, char *base64, uint32_t hexlength);
//uint32_t base64_decode(const char *base64, uint8_t *hexdata);
uint32_t base64_decode(const char *base64, uint8_t *hexdata, uint32_t base64length);

#endif
