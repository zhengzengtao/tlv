#ifndef __CRC_H__
#define __CRC_H__

#include <stdint.h>



uint32_t Cal_Crc32(uint32_t PartialCrc, uint8_t *Buffer, uint32_t Length);
uint16_t Cal_Crc16(uint16_t PartialCrc, uint8_t *Buffer, uint8_t Length);



#endif /*__CRC_H__ */
