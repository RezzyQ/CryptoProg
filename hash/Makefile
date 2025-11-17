# Компилятор и флаги
CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2
LDFLAGS = -lcryptopp

# Цели
TARGET = hash_tool
SOURCES = main.cpp
OBJECTS = $(SOURCES:.cpp=.o)

# Правила по умолчанию
.PHONY: all clean install uninstall test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

test: $(TARGET)
	@echo "Testing hash tool..."
	@echo "Creating test file..."
	echo "Hello, World!" > test.txt
	@echo "Calculating SHA256 hash..."
	./$(TARGET) test.txt
	@echo "Expected result (from command line):"
	@if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum test.txt; \
	elif command -v shasum >/dev/null 2>&1; then \
		shasum -a 256 test.txt; \
	else \
		echo "sha256sum or shasum not available for comparison"; \
	fi
	@rm -f test.txt

# Зависимости
main.o: main.cpp
