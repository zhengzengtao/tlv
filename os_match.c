#include "os_match.h"
#include <stdio.h>
#include <stdarg.h>


const dbgtype trance_level   = P_DEBUG;


void *z_malloc(size_t size)
{
	return malloc(size);
}

void *z_calloc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

void *z_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

void z_free(void* p)
{
	free(p);
}

int z_printf(dbgtype level, const char * format, ...)
{
	va_list arg;
	int done;
	
	if (level < trance_level)
	{
		return -1;
	}

	va_start (arg, format);
	done = vfprintf (stdout, format, arg);
	va_end (arg);

	return done;
}

int z_printf_str(dbgtype level, const char * str)
{
#ifdef __LPM2100_MEV3
	ECOMM_STRING(UNILOG_PLA_APP, AppTask_2, level, "%s", (const uint8_t *)str);
#endif
	return z_printf(level, "%s", str);
}
