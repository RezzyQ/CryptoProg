CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
LIBS = -lcryptopp

# Главная программа
crypto_tool: main.cpp
	$(CXX) $(CXXFLAGS) -o crypto_tool main.cpp $(LIBS)

# Очистка
clean:
	rm -f crypto_tool *.o test_* *.bin *.enc *.dec

# Тест
test: crypto_tool
	chmod +x test.sh
	./test.sh

# Для отладки
debug: CXXFLAGS += -g
debug: crypto_tool

.PHONY: clean test debug
