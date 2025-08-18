CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic
DEBUG_FLAGS = -g -fsanitize=address -fsanitize=undefined
LDFLAGS = 

SRCDIR = src
SOURCES = $(wildcard $(SRCDIR)/*.c)
TARGET = netscan

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -O2 -o $@ $^

debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

lint:
	cppcheck --enable=all --suppress=missingIncludeSystem $(SRCDIR)/

format:
	clang-format -i $(SRCDIR)/*.c include/*.h

memcheck: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) -h 127.0.0.1 -p 22

clean:
	rm -f $(TARGET)

.PHONY: all debug lint format memcheck clean