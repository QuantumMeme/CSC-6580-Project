CC = gcc
CFLAGS = -Wall

TARGETS = 00_hello_dynamic \
          01_hello_static \
          02_data_bss \
          03_custom_section \
          04_libsample.so \
          05_hello_stripped \
          06_constructor_test \
          07_minimal

all: $(TARGETS)

00_hello_dynamic: 00_hello_dynamic.c
	$(CC) $(CFLAGS) $< -o $@

01_hello_static: 01_hello_static.c
	$(CC) $(CFLAGS) -static $< -o $@

02_data_bss: 02_data_bss.c
	$(CC) $(CFLAGS) $< -o $@

03_custom_section: 03_custom_section.c
	$(CC) $(CFLAGS) $< -o $@

04_libsample.so: 04_libsample.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

05_hello_stripped: 05_hello_stripped.c
	$(CC) $(CFLAGS) $< -o $@
	strip $@

06_constructor_test: 06_constructor_test.c
	$(CC) $(CFLAGS) $< -o $@

07_minimal: 07_minimal.c
	$(CC) -nostdlib -nodefaultlibs -e _start $< -o $@

clean:
	rm -f $(TARGETS)
