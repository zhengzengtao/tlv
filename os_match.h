#ifndef __OS_MATCH_H__
#define __OS_MATCH_H__

#include <stdlib.h>
#include <stdint.h>
#ifdef __LPM2100_MEV3
#include "debug_log.h"
#include "debug_trace.h"
typedef debugTraceLevelType dbgtype;
#else
typedef uint8_t dbgtype;

typedef enum {
	P_DEBUG,		   /**< debug, lowest priority */
	P_INFO,			/**< info */
	P_VALUE,		   /**< value */
	P_SIG,			 /**< signalling/significant */
	P_WARNING,		 /**< warning */
	P_ERROR			/**< error, highest priority */
} TraceLevel;

#endif



#define BLURT z_printf(P_DEBUG, "This is line %d of file \"%s\" (function <%s>)\n", __LINE__, __FILE__, __func__)






void *z_malloc(size_t);
void *z_calloc(size_t nmemb, size_t size);
void *z_realloc(void *ptr, size_t size);
void z_free(void*);
int z_printf(dbgtype level, const char * format, ...);
int z_printf_str(dbgtype level, const char * str);

#endif  /* __OS_MATCH_H__ */
