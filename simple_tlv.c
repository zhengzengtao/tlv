#include <stdio.h>
#include <string.h>
#include "simple_tlv.h"
#include "base64.h"
#include "crc.h"
#ifdef ENCRYPT_DES
#include "des.h"
#endif
#ifdef ENCRYPT_AES
#include "aes128.h"
#endif



static int tlv_simple_generate(struct TLV_simple_Opr *, struct TLV_simple **, char **, uint32_t *);
static int tlv_simple_parse(struct TLV_simple_Opr *, struct TLV_simple**, char **, uint32_t);


static struct TLV_simple_Opr tlv_s_opr = {
	.deskey				= {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
	.aeskey				= {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
	.defaulttag			= 0x41,
	.defaultaddr		= 1,
	.defaultencryptmode	= 0,
	.key_scatter_factor	= {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 
	.generate			= tlv_simple_generate,
	.parse				= tlv_simple_parse,
};



static int tlv_simple_generate(struct TLV_simple_Opr *p_tlv_s_opr, struct TLV_simple** p_p_tlv_s, char ** p_p_chr, uint32_t *asciilength)
{
	uint32_t hexlen;
	uint32_t asciilen;
	uint32_t crc;
	char *chr = NULL;
	tlvlensize len = 0, effective_data_len = (*p_p_tlv_s)->effective_data_len;
	uint8_t *buffer;
	uint8_t key_scatter_factor[16];
	uint8_t tmpkey[16];
	int i;

	uint8_t		*tlv_tag;
	tlvlensize	*tlv_len;
	tlvaddsize	*tlv_addr;
	uint8_t		*tlv_encrypt_mode;
	tlvlensize	*tlv_effective_data_len;
	tlvcmdsize	*tlv_cmd;
	uint32_t	*tlv_crc;
	uint8_t		*tlv_data;
	uint8_t		*tlv_struct = NULL;
	tlvlensize	tlv_struct_size = sizeof(uint8_t) + sizeof(tlvlensize) + sizeof(tlvaddsize) + sizeof(uint8_t) + sizeof(tlvlensize) + sizeof(tlvcmdsize) + sizeof(uint32_t);
	tlvlensize	tlv_size = tlv_struct_size + effective_data_len;


	if ((*p_p_tlv_s)->cmd == 0)
	{
		return -2;
	}

	if (((*p_p_tlv_s)->tag & 0x1f) == 0x1f)
	{
		return -2;
	}

	if ((*p_p_tlv_s)->tag == 0)
	{
		(*p_p_tlv_s)->tag = p_tlv_s_opr->defaulttag;
	}

	if ((*p_p_tlv_s)->addr == 0)
	{
		(*p_p_tlv_s)->addr = p_tlv_s_opr->defaultaddr;
	}

	if ((*p_p_tlv_s)->encrypt_mode == 0)
	{
		(*p_p_tlv_s)->encrypt_mode = p_tlv_s_opr->defaultencryptmode;
	}

	memcpy(key_scatter_factor, p_tlv_s_opr->key_scatter_factor, 16);

	//(*p_p_tlv_s)->len = sizeof(struct TLV_simple) + (*p_p_tlv_s)->effective_data_len - sizeof(uint8_t) - sizeof(tlvlensize);
	(*p_p_tlv_s)->len = 0;
	(*p_p_tlv_s)->crc = 0;

	tlv_struct = (uint8_t *)z_malloc(tlv_size * sizeof(uint8_t));
	if (tlv_struct == NULL)
	{
		return -1;
	}

	i = 0;
	tlv_tag = &tlv_struct[i];
	*tlv_tag = (*p_p_tlv_s)->tag;
	i += sizeof(uint8_t);
	tlv_len = (tlvlensize *)&tlv_struct[i];
	*tlv_len = (*p_p_tlv_s)->len;
	i += sizeof(tlvlensize);
	tlv_addr = (tlvcmdsize *)&tlv_struct[i];
	*tlv_addr = (*p_p_tlv_s)->addr;
	i += sizeof(tlvaddsize);
	tlv_encrypt_mode = &tlv_struct[i];
	*tlv_encrypt_mode = (*p_p_tlv_s)->encrypt_mode;
	i += sizeof(uint8_t);
	tlv_effective_data_len = (tlvlensize *)&tlv_struct[i];
	*tlv_effective_data_len = (*p_p_tlv_s)->effective_data_len;
	i += sizeof(tlvlensize);
	tlv_cmd = (tlvcmdsize *)&tlv_struct[i];
	*tlv_cmd = (*p_p_tlv_s)->cmd;
	i += sizeof(tlvcmdsize);
	tlv_crc = (uint32_t *)&tlv_struct[i];
	*tlv_crc = 0;
	i += sizeof(uint32_t);
	tlv_data = &tlv_struct[i];
	memcpy(tlv_data, (*p_p_tlv_s)->data, effective_data_len);

	//crc = Cal_Crc32(0, (uint8_t *)(*p_p_tlv_s), sizeof(struct TLV_simple) + (*p_p_tlv_s)->effective_data_len);
	//(*p_p_tlv_s)->crc = crc;

	crc = Cal_Crc32(0, tlv_struct, tlv_size);
	*tlv_crc = crc;

#if 0	//for debug
	printf("Struct data: ");
	for (i = 0; i < tlv_size; i++)
	{
		printf("%02x ", tlv_struct[i]);
	}
	printf("\n");
#endif



#if (defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
	if (*tlv_encrypt_mode & 0x3)
	{
		/* *tlv_data struct:
		 *   byte [0 : 7] - Key scatter factor;
		 *   byte [8 : ~] - Encrypt data struct
		 * 		Encrypt data struct:	encrypt(cmd + origin data)
		 */

		len = 8;	/* Key scatter factor */
		effective_data_len += sizeof(tlvcmdsize);	/* include cmd */
	}
#endif

	if (effective_data_len)
	{
		if (*tlv_encrypt_mode & 0x2)
		{
#ifdef ENCRYPT_AES
			len += ((effective_data_len - 1) / 16 + 1) * 16;
#elif defined(ENCRYPT_DES)
			len += ((effective_data_len - 1) / 8 + 1) * 8;
#endif
		}
		else if (*tlv_encrypt_mode & 0x1)
		{
#ifdef ENCRYPT_DES
			len += ((effective_data_len - 1) / 8 + 1) * 8;
#endif
		}
		else
		{
			len += effective_data_len;
		}
	}
#if !(defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
	len = effective_data_len;
#endif 

	//*tlv_len = sizeof(struct TLV_simple) + *tlv_effective_data_len - sizeof(uint8_t) - sizeof(tlvlensize);
	//*tlv_len = sizeof(struct TLV_simple) + len - sizeof(uint8_t) - sizeof(tlvlensize);
	//*tlv_len = sizeof(struct TLV_simple) + len - (uint8_t)((char*)&*tlv_addr - (char*)&*tlv_tag);
	*tlv_len = tlv_struct_size + len - (uint8_t)((char*)&*tlv_addr - (char*)&*tlv_tag);
	//printf("%p, %ld", &*tlv_tag, (char*)&*tlv_addr - (char*)&*tlv_tag);

	//hexlen = *tlv_len + sizeof(uint8_t) + sizeof(tlvlensize);
	//hexlen = sizeof(struct TLV_simple) + len;
	hexlen = tlv_struct_size + len;
	asciilen = hexlen * 2;

	if (len)
	{
		//*p_p_tlv_s = (struct TLV_simple *)z_realloc(*p_p_tlv_s, (sizeof(struct TLV_simple) + len) * sizeof(uint8_t));
		tlv_struct = (uint8_t *)z_realloc(tlv_struct, hexlen * sizeof(uint8_t));

		buffer = (uint8_t *)z_malloc(len * 2 * sizeof(uint8_t));
		if (buffer == NULL)
		{
			if (tlv_struct != NULL)
			{
				free(tlv_struct);
				tlv_struct = NULL;
			}
			return -1;
		}

#if (defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
		if (*tlv_encrypt_mode & 0x3)
		{
			memcpy(buffer, (uint8_t *)&*tlv_cmd, sizeof(tlvcmdsize));	
			*tlv_cmd = 0;
			memcpy(&buffer[sizeof(tlvcmdsize)], tlv_data, *tlv_effective_data_len);

			if (*tlv_encrypt_mode & 0x1)
			{
#ifdef ENCRYPT_DES
				//int tdesEncrypt(unsigned char *In, unsigned char *Out, unsigned char *Key, unsigned int Len);
				tdesEncrypt(key_scatter_factor, tmpkey, p_tlv_s_opr->deskey, 16);

				//int tdesEncrypt(unsigned char *In, unsigned char *Out, unsigned char *Key, unsigned int Len);
				tdesEncrypt(buffer, &buffer[len], tmpkey, len - 8);
				memcpy(buffer, &buffer[len], len);
#endif
			}

			if (*tlv_encrypt_mode & 0x2)
			{
#ifdef ENCRYPT_AES
				//int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len);
				aesDecrypt(p_tlv_s_opr->aeskey, 16, key_scatter_factor, tmpkey, 16);

				//int aesEncrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *pt, uint8_t *ct, uint32_t len);
				aesEncrypt(tmpkey, 16, buffer, &buffer[len], len - 8);
				memcpy(buffer, &buffer[len], len);
#endif
			}

#if (defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
			memcpy(tlv_data, &key_scatter_factor[p_tlv_s_opr->role * 8], 8);
			memcpy(&tlv_data[8], buffer, len - 8);
#endif
		}
#endif

		free(buffer);
		buffer = NULL;
	}


	chr = (char *)z_calloc(asciilen, sizeof(uint8_t));
	if (chr == NULL)
	{
		if (tlv_struct != NULL)
		{
			free(tlv_struct);
			tlv_struct = NULL;
		}
		return -1;
	}

#if 0	//for debug
	//printf("tlv_size = %d, hexlen = %d\r\n", tlv_size, hexlen);
	printf("Struct data: ");
	for (i = 0; i < tlv_size; i++)
	{
		printf("%02x ", tlv_struct[i]);
	}
	printf("\n");
#endif

	//uint32_t base64_encode(const uint8_t *hexdata, char *base64, uint32_t hexlength);
	//asciilen = base64_encode((uint8_t *)*p_p_tlv_s, chr, hexlen);
	asciilen = base64_encode(tlv_struct, chr, hexlen);


	char *chr2 = (char *)z_calloc(asciilen + 1, sizeof(char));		/* fix the size */
	memcpy(chr2, chr, asciilen);
	free(chr);
	chr = NULL;

	*p_p_chr = chr2;
	chr2[asciilen] = '\0';

	*asciilength = asciilen + 1;

	free(*p_p_tlv_s);
	*p_p_tlv_s = NULL;

	return 0;
}

static int tlv_simple_parse(struct TLV_simple_Opr *p_tlv_s_opr, struct TLV_simple** p_p_tlv_s, char ** p_p_chr, uint32_t asciilength)
{
	//struct TLV_simple *t = NULL;
	uint32_t len = 0, effective_data_len;
	uint8_t *buffer = NULL;
	uint32_t crc;
	uint8_t key_scatter_factor[16];
	uint8_t tmpkey[16];
	int i;

	uint8_t		*tlv_tag;
	tlvlensize	*tlv_len;
	tlvaddsize	*tlv_addr;
	uint8_t		*tlv_encrypt_mode;
	tlvlensize	*tlv_effective_data_len;
	tlvcmdsize	*tlv_cmd;
	uint32_t	*tlv_crc;
	uint8_t		*tlv_data;
	uint8_t		*tlv_struct = NULL;
	tlvlensize	tlv_struct_size = sizeof(uint8_t) + sizeof(tlvlensize) + sizeof(tlvaddsize) + sizeof(uint8_t) + sizeof(tlvlensize) + sizeof(tlvcmdsize) + sizeof(uint32_t);
	tlvlensize	tlv_size;


	tlv_struct = (uint8_t *)z_calloc(asciilength, sizeof(uint8_t));
	if (tlv_struct == NULL)
	{
		return -1;
	}

	i = 0;
	tlv_tag = &tlv_struct[i];
	i += sizeof(uint8_t);
	tlv_len = (tlvlensize *)&tlv_struct[i];
	i += sizeof(tlvlensize);
	tlv_addr = (tlvcmdsize *)&tlv_struct[i];
	i += sizeof(tlvaddsize);
	tlv_encrypt_mode = &tlv_struct[i];
	i += sizeof(uint8_t);
	tlv_effective_data_len = (tlvlensize *)&tlv_struct[i];
	i += sizeof(tlvlensize);
	tlv_cmd = (tlvcmdsize *)&tlv_struct[i];
	i += sizeof(tlvcmdsize);
	tlv_crc = (uint32_t *)&tlv_struct[i];
	i += sizeof(uint32_t);
	tlv_data = &tlv_struct[i];


	//uint32_t base64_decode(const char *base64, uint8_t *hexdata, uint32_t base64length);
	len = base64_decode(*p_p_chr, tlv_struct, asciilength);
#if 0	//for debug
	printf("data received: ");
	for (i = 0; i < len; i++)
	{
		printf("%02x", tlv_struct[i]);
	}
	printf("\n");
#endif

	//if (len != t->len + sizeof(uint8_t) + sizeof(tlvlensize))
	if (len < *tlv_len + (uint8_t)((char*)tlv_addr - (char*)tlv_tag))
	{
		z_printf(P_DEBUG, "len = %d, *tlv_len = %d, diff %d\n", len, *tlv_len, (uint8_t)((char*)tlv_addr - (char*)tlv_tag));
		return -2;
	}

	len = *tlv_len + (uint8_t)((char*)tlv_addr - (char*)tlv_tag);

	//*p_p_tlv_s = t;

#if 0	//for debug
	printf("Struct data: ");
	for (i = 0; i < sizeof(struct TLV_simple) + (*p_p_tlv_s)->effective_data_len; i++)
	{
		printf("%02x ", ((uint8_t *)(*p_p_tlv_s))[i]);
	}
	printf("\n");
#endif

	free(*p_p_chr);
	*p_p_chr = NULL;

	effective_data_len = *tlv_effective_data_len;

#if (defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
	if (*tlv_encrypt_mode & 0x3)
	{
		/* (*p_p_tlv_s)->data struct:
		 *   byte [0 : 7] - Key scatter factor;
		 *   byte [8 : ~] - Encrypt data struct
		 * 		Encrypt data struct:	encrypt(cmd + origin data)
		 */

		len = 8;	/* Key scatter factor */
		effective_data_len += sizeof(tlvcmdsize);	/* include cmd */
	}
#endif

	if (effective_data_len)
	{
		if (*tlv_encrypt_mode & 0x2)
		{
#ifdef ENCRYPT_AES
			len += ((effective_data_len - 1) / 16 + 1) * 16;
#elif defined(ENCRYPT_DES)
			len += ((effective_data_len - 1) / 8 + 1) * 8;
#endif
		}
		else if (*tlv_encrypt_mode & 0x1)
		{
#ifdef ENCRYPT_DES
			len += ((effective_data_len - 1) / 8 + 1) * 8;
#endif
		}
		else
		{
			len += effective_data_len;
		}
	}
#if !(defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
	len = effective_data_len;
#endif 


	if (len)
	{
#if (defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
		if (*tlv_encrypt_mode & 0x3)
		{
			buffer = (uint8_t *)z_malloc(len * 2 * sizeof(uint8_t));
			memcpy(key_scatter_factor, p_tlv_s_opr->key_scatter_factor, 16);
			memcpy(&key_scatter_factor[((p_tlv_s_opr->role) ^ 1) * 8], tlv_data, 8);

			memcpy(buffer, &tlv_data[8], len - 8);

			if (*tlv_encrypt_mode & 0x2)
			{
#ifdef ENCRYPT_AES
				//int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len);
				aesDecrypt(p_tlv_s_opr->aeskey, 16, key_scatter_factor, tmpkey, 16);

				//int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len);
				aesDecrypt(tmpkey, 16, buffer, &buffer[len], len - 8);
				memcpy(buffer, &buffer[len], len);
#endif
			}

			if (*tlv_encrypt_mode & 0x1)
			{
#ifdef ENCRYPT_DES
				//int tdesEncrypt(unsigned char *In, unsigned char *Out, unsigned char *Key, unsigned int Len);
				tdesEncrypt(key_scatter_factor, tmpkey, p_tlv_s_opr->deskey, 16);

				//int tdesDecrypt(unsigned char *In, unsigned char *Out, unsigned char *Key, unsigned int Len);
				tdesDecrypt(buffer, &buffer[len], tmpkey, len - 8);
				memcpy(buffer, &buffer[len], len);
#endif
			}

			memcpy(tlv_cmd, buffer, sizeof(tlvcmdsize));
			memcpy(tlv_data, &buffer[sizeof(tlvcmdsize)], *tlv_effective_data_len);

			free(buffer);
			buffer = NULL;
		}
#endif
	}

	len = *tlv_len;
	*tlv_len = 0;
	crc = *tlv_crc;
	*tlv_crc = 0;
	tlv_size = tlv_struct_size + *tlv_effective_data_len;

	if (crc != Cal_Crc32(0, tlv_struct, tlv_struct_size + *tlv_effective_data_len))
	{
		return -3;
	}

	//t->crc = crc;

	*p_p_tlv_s = (struct TLV_simple *)z_calloc(sizeof(struct TLV_simple) + *tlv_effective_data_len, sizeof(uint8_t));
	if (*p_p_tlv_s == NULL)
	{
		return -1;
	}

	(*p_p_tlv_s)->tag = *tlv_tag;
	(*p_p_tlv_s)->len = len;
	(*p_p_tlv_s)->addr = *tlv_addr;
	(*p_p_tlv_s)->encrypt_mode = *tlv_encrypt_mode;
	(*p_p_tlv_s)->effective_data_len = *tlv_effective_data_len;
	(*p_p_tlv_s)->cmd = *tlv_cmd;
	(*p_p_tlv_s)->crc = crc;
	if (*tlv_effective_data_len)
	{
		memcpy((*p_p_tlv_s)->data, tlv_data, *tlv_effective_data_len);
	}

	free(tlv_struct);
	tlv_struct = NULL;


	return 0;
}


struct TLV_simple_Opr *get_tlv_s_opr(void)
{
	return &tlv_s_opr;
}

