# TouchFrame radio dongle firmware (nRF52840 Dongle). Run ./build.sh rather than make directly
# on Windows: it puts the Arm toolchain on PATH.
#   make            -> build/touchframe-radio.{elf,hex,zip}
#   make flash      -> reboot the dongle into its bootloader and flash over USB (tools/radio.py dfu)

PROJECT = touchframe-radio
BUILD = build
TP = third_party
CROSS ?= arm-none-eabi-
CC = $(CROSS)gcc
OBJCOPY = $(CROSS)objcopy
SIZE = $(CROSS)size
NRFUTIL ?= nrfutil
PYTHON ?= python

SRC_C = \
  src/main.c \
  src/sniffer.c \
  src/usb_descriptors.c \
  $(TP)/nrfx/mdk/system_nrf52840.c \
  $(TP)/tinyusb/src/tusb.c \
  $(TP)/tinyusb/src/common/tusb_fifo.c \
  $(TP)/tinyusb/src/device/usbd.c \
  $(TP)/tinyusb/src/device/usbd_control.c \
  $(TP)/tinyusb/src/class/cdc/cdc_device.c \
  $(TP)/tinyusb/src/portable/nordic/nrf5x/dcd_nrf5x.c
SRC_C := $(wildcard $(SRC_C))
SRC_S = $(TP)/nrfx/mdk/gcc_startup_nrf52840.S

INC = \
  src \
  $(TP)/tinyusb/src \
  $(TP)/tinyusb/hw/bsp/nrf/nrfx_config \
  $(TP)/nrfx \
  $(TP)/nrfx/mdk \
  $(TP)/nrfx/hal \
  $(TP)/nrfx/drivers/include \
  $(TP)/cmsis/CMSIS/Core/Include

CPU = -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16
DEFS = -DNRF52840_XXAA -D__STARTUP_CLEAR_BSS -D__HEAP_SIZE=0 -D__STACK_SIZE=8192 -D__START=main
CFLAGS = $(CPU) $(DEFS) $(addprefix -I,$(INC)) -std=gnu11 -Os -g -Wall -Wextra \
  -Wno-unused-parameter -ffunction-sections -fdata-sections -fno-strict-aliasing -MMD -MP
LDFLAGS = $(CPU) -nostartfiles --specs=nosys.specs --specs=nano.specs -Wl,--gc-sections -Wl,--no-warn-rwx-segments \
  -L$(TP)/nrfx/mdk -T pca10059.ld -Wl,-Map=$(BUILD)/$(PROJECT).map

OBJ = $(addprefix $(BUILD)/obj/,$(SRC_C:.c=.o) $(SRC_S:.S=.o))

all: $(BUILD)/$(PROJECT).zip

$(BUILD)/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/obj/%.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(CPU) $(DEFS) $(addprefix -I,$(INC)) -c $< -o $@

$(BUILD)/$(PROJECT).elf: $(OBJ) pca10059.ld
	$(CC) $(LDFLAGS) $(OBJ) -o $@
	$(SIZE) $@

$(BUILD)/$(PROJECT).hex: $(BUILD)/$(PROJECT).elf
	$(OBJCOPY) -O ihex $< $@

# Unsigned package for the dongle's open bootloader.
$(BUILD)/$(PROJECT).zip: $(BUILD)/$(PROJECT).hex
	$(NRFUTIL) nrf5sdk-tools pkg generate --hw-version 52 --sd-req 0x00 --debug-mode \
	  --application $< $@

flash: $(BUILD)/$(PROJECT).zip
	$(PYTHON) ../tools/radio.py dfu --package $<

clean:
	rm -rf $(BUILD)

.PHONY: all flash clean
-include $(OBJ:.o=.d)
