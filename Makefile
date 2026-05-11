CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2
LDFLAGS ?=
LDLIBS ?= -lncurses -lm

TARGET = passgen
WORDLIST = eff_large_wordlist.txt
WORDLIST_URL = https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt

.PHONY: all clean test

all: $(WORDLIST) $(TARGET)

$(WORDLIST):
	curl -L --fail --silent --show-error "$(WORDLIST_URL)" -o "$@"

$(TARGET): passgen.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ passgen.c $(LDLIBS)

test: passgen.c $(WORDLIST)
	$(CC) $(CFLAGS) -DPASSGEN_TEST -o passgen_test passgen.c -lm
	./passgen_test

clean:
	rm -f $(TARGET) passgen_test
