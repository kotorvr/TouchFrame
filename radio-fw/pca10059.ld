/* nRF52840 Dongle (PCA10059) with Nordic's MBR (0x0) and open USB bootloader (0xE0000).
   The application lives between them; the MBR keeps the first 8 bytes of RAM. */
SEARCH_DIR(.)

MEMORY
{
  FLASH (rx) : ORIGIN = 0x1000, LENGTH = 0xDF000
  RAM (rwx) :  ORIGIN = 0x20000008, LENGTH = 0x3fff8
}

INCLUDE "nrf_common.ld"
