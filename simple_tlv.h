#ifndef __SIMPLE_TLV__
#define __SIMPLE_TLV__

#include <stdint.h>
#include "os_match.h"

#if 0	//for debug
#define ENCRYPT_DES
#define ENCRYPT_AES
#endif

typedef uint16_t tlvlensize;
typedef uint16_t tlvaddsize;
typedef uint16_t tlvcmdsize;

enum ROLES
{
	INITIATOR,
	RESPONDER,
};


struct TLV_simple
{
	uint8_t				tag;
	tlvlensize			len;
	tlvaddsize  		addr;	/* 0- reserved; max value(all bits are 1)- boardcast */
	uint8_t				encrypt_mode;	/* bit0: 3des; bit1: aes128 */
	tlvlensize			effective_data_len;
	tlvcmdsize			cmd;
	uint32_t			crc;
	uint8_t				data[];
};



struct TLV_simple_Opr
{
	uint8_t				deskey[16];
	uint8_t				aeskey[16];
	uint8_t				defaulttag;
	tlvaddsize			defaultaddr;
	uint8_t				role;
	uint8_t				defaultencryptmode;
	uint8_t				key_scatter_factor[16];
	int					(*generate)(struct TLV_simple_Opr *, struct TLV_simple**, char **, uint32_t *);
	int					(*parse)(struct TLV_simple_Opr *, struct TLV_simple**, char **, uint32_t);
};



struct TLV_simple_Opr *get_tlv_s_opr(void);

#endif /* __SIMPLE_TLV__ */
