#include <stdio.h>
#include <string.h>
#include "simple_tlv.h"
#include "os_match.h"




int main(int argc, char *argv[])
{
	struct TLV_simple *t = NULL;
	tlvcmdsize cmd = 2;		/* just for test */
	tlvlensize len = 0;	/* also just for test */
	uint8_t data[1000] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9};	/* still for test */
	char *chr = NULL;
	struct TLV_simple_Opr *p_tlv_s_opr = get_tlv_s_opr();
	uint32_t i, asciilen;
	uint8_t *ksf_initiator = p_tlv_s_opr->key_scatter_factor;			/* Initiator Key Dispersion Factor */
	uint8_t *ksf_responder = &(p_tlv_s_opr->key_scatter_factor)[8];		/* Responder Key Dispersion Factor */
	//char reply[] = "Qg8AAQAABAACAATkSmYAAAAA";
	char reply[] = "Qg8AAQAABAACALy1WWgACAAA";
	

	BLURT;
	printf("t = %p, chr = %p\n", t, chr);

	t = (struct TLV_simple *)z_calloc(sizeof(struct TLV_simple) + len, sizeof(uint8_t));
	if (t == NULL)
	{
		return -1;
	}

	BLURT;
	printf("t = %p, chr = %p\n", t, chr);

	t->tag = 0x41;
	t->addr = 0x1;	/* target addr */
	t->encrypt_mode = 0;
	t->effective_data_len = len;
	t->cmd = cmd;
	if (len)
	{
		memcpy(t->data, data, len);
	}

	p_tlv_s_opr->role = INITIATOR;
	
	for (i = 0; i < 8; i++)
	{
		ksf_initiator[i] = i;
	}

	for (i = 0; i < 8; i++)
	{
		ksf_responder[i] = i | (i << 4);
	}

	i = p_tlv_s_opr->generate(p_tlv_s_opr, &t, &chr, &asciilen);

	if (i)
	{
		printf("Error! code %d\n", i);
		return -1;
	}

	printf("ascii length = %d\n%s\n", asciilen, chr);

	for (i = 0; i < asciilen; i++)
	{
		printf("%02x", chr[i]);
	}

	printf("\n");

	BLURT;
	printf("t = %p, chr = %p\n", t, chr);

	p_tlv_s_opr->role = RESPONDER;

#if 1
	asciilen = sizeof(reply);
	free(chr);
	chr = NULL;
	chr = (char *)malloc(asciilen * sizeof(uint8_t));
	memcpy(chr, reply, asciilen);
#endif

	i = p_tlv_s_opr->parse(p_tlv_s_opr, &t, &chr, asciilen);	

	if (i)
	{
		printf("Error! code %d\n", i);
		return -1;
	}


	printf("t->tag = 0x%02x\n", t->tag);
	printf("t->len = %d\n", t->len);
	printf("t->addr = %d\n", t->addr);
	printf("t->encrypt_mode = %d\n", t->encrypt_mode);
	printf("t->effective_data_len = %d\n", t->effective_data_len);
	printf("t->cmd = 0x%x\n", t->cmd);
	printf("t->crc = %d\n", t->crc);
	printf("t->data: ");
	for (i=0; i<t->effective_data_len; i++)
	{
		printf("%02x ", t->data[i]);
	}
	printf("\n");


	BLURT;
	printf("t = %p, chr = %p\n", t, chr);

	free(t);
	t = NULL;

	BLURT;
	printf("t = %p, chr = %p\n", t, chr);

	return 0;
}

