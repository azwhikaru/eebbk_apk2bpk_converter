CC ?= clang
CFLAGS = -Wall -O2
LD = $(CC)
#STRIP = strip

INCLUDES = -I.

LDFLAGS = -static -s

src = apk2bpk.c
ext =

ifeq ($(shell echo $$OS), Windows_NT)
src += mman.c
CFLAGS += -I.
ext += .exe
endif

obj = $(patsubst %.c,%.o,$(src))

.PHONY: all

all: apk2bpk$(ext)

%.o: %.c
	@echo "    CC $@"
	@$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

apk2bpk$(ext): $(obj)
	@echo "    LD $@"
	@$(LD) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	$(RM) *.o
	$(RM) apk2bpk$(ext)

test: apk2bpk$(ext)
	./apk2bpk -i test.apk
	