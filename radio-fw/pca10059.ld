/* nRF52840 Dongle (PCA10059) with Nordic's MBR (0x0) and open USB bootloader (0xE0000).
   The application lives between them, minus the top 3 pages (0xDD000..0xDFFFF): the bootloader's
   app data area, kept across DFU. The flash store (src/store.h: identity + pairings) uses
   0xDE000 and 0xDF000. The MBR keeps the first 8 bytes of RAM. */
SEARCH_DIR(.)

MEMORY
{
  FLASH (rx) : ORIGIN = 0x1000, LENGTH = 0xDC000
  RAM (rwx) :  ORIGIN = 0x20000008, LENGTH = 0x3fff8
}

INCLUDE "nrf_common.ld"
