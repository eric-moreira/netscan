CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99
DEBUG_FLAGS = -g -fsanitize=address -fsanitize=undefined
LDFLAGS = 

SRCDIR = src
TESTDIR = tests
INCLUDEDIR = include
SOURCES = $(wildcard $(SRCDIR)/*.c)
TEST_SOURCES = $(wildcard $(TESTDIR)/*.c)
TARGET = netscan
TEST_TARGET = test_runner

# Main sources (excluding main.c for library)
LIB_SOURCES = $(filter-out $(SRCDIR)/main.c, $(SOURCES))

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -O2 -o $@ $^

# Build test runner
$(TEST_TARGET): $(TEST_SOURCES) $(LIB_SOURCES)
	$(CC) $(CFLAGS) -I$(INCLUDEDIR) -o $@ $^

# Run tests
test: $(TEST_TARGET)
	@echo "=== Running Tests ==="
	./$(TEST_TARGET)

debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

debug-test: CFLAGS += $(DEBUG_FLAGS)
debug-test: $(TEST_TARGET)

lint:
	cppcheck --enable=all --suppress=missingIncludeSystem $(SRCDIR)/ $(TESTDIR)/

format:
	clang-format -i $(SRCDIR)/*.c $(TESTDIR)/*.c $(INCLUDEDIR)/*.h

memcheck: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) -h 127.0.0.1 -p 22

memcheck-test: $(TEST_TARGET)
	valgrind --leak-check=full --show-leak-kinds=all ./$(TEST_TARGET)

clean:
	rm -f $(TARGET) $(TEST_TARGET)

fast:$(TARGET)

$(TARGET): $(SOURCES)
	$(CC) -o $@ $^

.PHONY: all debug test debug-test lint format memcheck memcheck-test clean