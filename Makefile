TARGET = main
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -Iinclude -g

# Флаги для libnetfilter_queue
PKG_CONFIG = pkg-config
NFQ_CFLAGS = $(shell $(PKG_CONFIG) --cflags libnetfilter_queue)
NFQ_LIBS = $(shell $(PKG_CONFIG) --libs libnetfilter_queue)

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

SRC = $(shell find $(SRC_DIR) -name '*.cpp')
OBJ = $(SRC:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

# Добавляем флаги NFQ
CXXFLAGS += $(NFQ_CFLAGS)
LDFLAGS = $(NFQ_LIBS)

all: $(BIN_DIR)/$(TARGET)

$(BIN_DIR)/$(TARGET): $(OBJ)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

# Проверка зависимостей
check-deps:
	@echo "Проверка зависимостей..."
	@pkg-config --exists libnetfilter_queue || (echo "Ошибка: libnetfilter_queue не установлена" && false)
	@echo "Все зависимости найдены"

# Установка зависимостей (для Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y libnetfilter-queue-dev libnfnetlink-dev pkg-config

# Отладочная цель
debug: CXXFLAGS += -DDEBUG -O0
debug: all

# Релизная сборка
release: CXXFLAGS += -O2 -DNDEBUG
release: all

.PHONY: all clean check-deps install-deps debug release