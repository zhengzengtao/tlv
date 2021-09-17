#include "base64.h"

const static char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint32_t base64_encode(const uint8_t *hexdata, char *base64, uint32_t hexlength)
{
	uint32_t i, j;
	uint8_t current;

	for (i = 0, j = 0; i < hexlength; i += 3)
	{
		current = (hexdata[i] >> 2);
		current &= (uint8_t)0x3F;
		base64[j++] = base64char[(int)current];

		current = ((uint8_t)(hexdata[i] << 4 )) & ((uint8_t)0x30);
		if (i + 1 >= hexlength)
		{
			base64[j++] = base64char[(int)current];
			base64[j++] = '=';
			base64[j++] = '=';

			break;
		}
		current |= ((uint8_t)(hexdata[i + 1] >> 4)) & ((uint8_t)0x0f);
		base64[j++] = base64char[(int)current];

		current = ((uint8_t)(hexdata[i+1] << 2)) & ((uint8_t)0x3c);
		if (i + 2 >= hexlength)
		{
			base64[j++] = base64char[(int)current];
			base64[j++] = '=';

			break;
		}
		current |= ((uint8_t)(hexdata[i + 2] >> 6)) & ((uint8_t)0x03);
		base64[j++] = base64char[(int)current];

		current = ((uint8_t)hexdata[i + 2]) & ((uint8_t)0x3f);
		base64[j++] = base64char[(int)current];
	}

	base64[j] = '\0';
	
	return j;
}

uint32_t base64_decode(const char *base64, uint8_t *hexdata, uint32_t base64length)
{
	int i, j;
	uint8_t k;
	uint8_t temp[4];
	//for (i = 0, j = 0; base64[i] != '\0' ; i += 4)
	for (i = 0, j = 0; i < base64length; i += 4)
	{
		memset(temp, 0xff, sizeof(temp));
		for (k = 0 ; k < 64 ; k++)
		{
			if (base64char[k] == base64[i])
			{
				temp[0] = k;
			}
		}
		
		for (k = 0 ; k < 64 ; k++)
		{
			if (base64char[k] == base64[i + 1])
			{
				temp[1] = k;
			}
		}

		for (k = 0 ; k < 64 ; k++)
		{
			if (base64char[k] == base64[i + 2])
			{
				temp[2] = k;
			}
		}
		for (k = 0 ; k < 64 ; k++)
		{
			if (base64char[k] == base64[i + 3])
			{
				temp[3] = k;
			}
		}

		hexdata[j++] = ((uint8_t)(((uint8_t)(temp[0] << 2)) & 0xfc)) | ((uint8_t)((uint8_t)(temp[1] >> 4) & 0x03));
		if (base64[i + 2] == '=')
		{
			break;
		}

		hexdata[j++] = ((uint8_t)(((uint8_t)(temp[1] << 4)) & 0xf0)) | ((uint8_t)((uint8_t)(temp[2] >> 2) & 0x0f));
		if (base64[i + 3] == '=' )
		{
			break;
		}

		hexdata[j++] = ((uint8_t)(((uint8_t)(temp[2] << 6) ) & 0xf0)) | ((uint8_t)(temp[3] & 0x3f));
	}
	
	return j;
}
