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

	crc = Cal_Crc32(0, (uint8_t *)(*p_p_tlv_s), sizeof(struct TLV_simple) + (*p_p_tlv_s)->effective_data_len);
	(*p_p_tlv_s)->crc = crc;


#if (defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
	if ((*p_p_tlv_s)->encrypt_mode & 0x3)
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
		if ((*p_p_tlv_s)->encrypt_mode & 0x2)
		{
#ifdef ENCRYPT_AES
			len += ((effective_data_len - 1) / 16 + 1) * 16;
#elif defined(ENCRYPT_DES)
			len += ((effective_data_len - 1) / 8 + 1) * 8;
#endif
		}
		else if ((*p_p_tlv_s)->encrypt_mode & 0x1)
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

	//(*p_p_tlv_s)->len = sizeof(struct TLV_simple) + (*p_p_tlv_s)->effective_data_len - sizeof(uint8_t) - sizeof(tlvlensize);
	(*p_p_tlv_s)->len = sizeof(struct TLV_simple) + len - sizeof(uint8_t) - sizeof(tlvlensize);

	hexlen = (*p_p_tlv_s)->len + sizeof(uint8_t) + sizeof(tlvlensize);
	asciilen = hexlen * 2;

	if (len)
	{
		*p_p_tlv_s = (struct TLV_simple *)z_realloc(*p_p_tlv_s, (sizeof(struct TLV_simple) + len) * sizeof(uint8_t));

		buffer = (uint8_t *)z_malloc(len * 2 * sizeof(uint8_t));
		if (buffer == NULL)
		{
			return -1;
		}

#if (defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
		if ((*p_p_tlv_s)->encrypt_mode & 0x3)
		{
			memcpy(buffer, (uint8_t *)&(*p_p_tlv_s)->cmd, sizeof(tlvcmdsize));	
			(*p_p_tlv_s)->cmd = 0;
			memcpy(&buffer[sizeof(tlvcmdsize)], (*p_p_tlv_s)->data, (*p_p_tlv_s)->effective_data_len);

			if ((*p_p_tlv_s)->encrypt_mode & 0x1)
			{
#ifdef ENCRYPT_DES
				//int tdesEncrypt(unsigned char *In, unsigned char *Out, unsigned char *Key, unsigned int Len);
				tdesEncrypt(key_scatter_factor, tmpkey, p_tlv_s_opr->deskey, 16);

				//int tdesEncrypt(unsigned char *In, unsigned char *Out, unsigned char *Key, unsigned int Len);
				tdesEncrypt(buffer, &buffer[len], tmpkey, len - 8);
				memcpy(buffer, &buffer[len], len);
#endif
			}

			if ((*p_p_tlv_s)->encrypt_mode & 0x2)
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
			memcpy((*p_p_tlv_s)->data, &key_scatter_factor[p_tlv_s_opr->role * 8], 8);
			memcpy(&(*p_p_tlv_s)->data[8], buffer, len - 8);
#endif
		}
#endif

		free(buffer);
		buffer = NULL;
	}


	chr = (char *)z_calloc(asciilen, sizeof(uint8_t));
	if (chr == NULL)
	{
		return -1;
	}

	//uint32_t base64_encode(const uint8_t *hexdata, char *base64, uint32_t hexlength);
	asciilen = base64_encode((uint8_t *)*p_p_tlv_s, chr, hexlen);


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
	struct TLV_simple *t = NULL;
	uint32_t len = 0, effective_data_len;
	uint8_t *buffer = NULL;
	uint32_t crc;
	uint8_t key_scatter_factor[16];
	uint8_t tmpkey[16];
	int i;

	t = (struct TLV_simple *)z_calloc(asciilength, sizeof(uint8_t));
	if (t == NULL)
	{
		return -1;
	}

	//uint32_t base64_decode(const char *base64, uint8_t *hexdata, uint32_t base64length);
	len = base64_decode(*p_p_chr, (uint8_t *)t, asciilength);
	if (len != t->len + sizeof(uint8_t) + sizeof(tlvlensize))
	{
		return -2;
	}

	*p_p_tlv_s = t;

	free(*p_p_chr);
	*p_p_chr = NULL;

	effective_data_len = t->effective_data_len;

#if (defined(ENCRYPT_DES) || defined(ENCRYPT_AES))
	if (t->encrypt_mode & 0x3)
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
		if ((*p_p_tlv_s)->encrypt_mode & 0x2)
		{
#ifdef ENCRYPT_AES
			len += ((effective_data_len - 1) / 16 + 1) * 16;
#elif defined(ENCRYPT_DES)
			len += ((effective_data_len - 1) / 8 + 1) * 8;
#endif
		}
		else if ((*p_p_tlv_s)->encrypt_mode & 0x1)
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
		if (t->encrypt_mode & 0x3)
		{
			buffer = (uint8_t *)z_malloc(len * 2 * sizeof(uint8_t));
			memcpy(key_scatter_factor, p_tlv_s_opr->key_scatter_factor, 16);
			memcpy(&key_scatter_factor[((p_tlv_s_opr->role) ^ 1) * 8], t->data, 8);

			memcpy(buffer, &t->data[8], len - 8);

			if (t->encrypt_mode & 0x2)
			{
#ifdef ENCRYPT_AES
				//int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len);
				aesDecrypt(p_tlv_s_opr->aeskey, 16, key_scatter_factor, tmpkey, 16);

				//int aesDecrypt(const uint8_t *key, uint32_t keyLen, const uint8_t *ct, uint8_t *pt, uint32_t len);
				aesDecrypt(tmpkey, 16, buffer, &buffer[len], len - 8);
				memcpy(buffer, &buffer[len], len);
#endif
			}

			if (t->encrypt_mode & 0x1)
			{
#ifdef ENCRYPT_DES
				//int tdesEncrypt(unsigned char *In, unsigned char *Out, unsigned char *Key, unsigned int Len);
				tdesEncrypt(key_scatter_factor, tmpkey, p_tlv_s_opr->deskey, 16);

				//int tdesDecrypt(unsigned char *In, unsigned char *Out, unsigned char *Key, unsigned int Len);
				tdesDecrypt(buffer, &buffer[len], tmpkey, len - 8);
				memcpy(buffer, &buffer[len], len);
#endif
			}

			memcpy((uint8_t *)&t->cmd, buffer, sizeof(tlvcmdsize));
			memcpy(t->data, &buffer[sizeof(tlvcmdsize)], t->effective_data_len);

			free(buffer);
			buffer = NULL;
		}
#endif
	}

	crc = t->crc;
	t->len = 0;
	t->crc = 0;

	if (crc != Cal_Crc32(0, (uint8_t *)t, sizeof(struct TLV_simple) + t->effective_data_len))
	{
		return -3;
	}

	t->crc = crc;

	return 0;
}


struct TLV_simple_Opr *get_tlv_s_opr(void)
{
	return &tlv_s_opr;
}

