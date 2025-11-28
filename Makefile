# Компилятор и флаги
CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17

# Директории
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Основное приложение
MAIN_TARGET = main
MAIN_SRC_DIRS = $(SRC_DIR)/core $(SRC_DIR)/ui $(SRC_DIR)
MAIN_SOURCES = $(foreach dir,$(MAIN_SRC_DIRS),$(wildcard $(dir)/*.cpp))
MAIN_OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(MAIN_SOURCES))
MAIN_INCLUDES = -I$(INCLUDE_DIR)

# Демон nfqws
DEAMON_TARGET = nfqwsDeamon
DEAMON_ROOT = $(SRC_DIR)/services/nfqwsD
DEAMON_SRC_DIRS = $(DEAMON_ROOT)/src $(DEAMON_ROOT)/attacks/src $(SRC_DIR)/services
DEAMON_SOURCES = $(foreach dir,$(DEAMON_SRC_DIRS),$(wildcard $(dir)/*.cpp))
DEAMON_OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(DEAMON_SOURCES))
DEAMON_INCLUDES = -I$(DEAMON_ROOT)/include -I$(DEAMON_ROOT)/attacks/include -I$(INCLUDE_DIR)
DEAMON_LIBS = -lnetfilter_queue

# ---------------------------------------------------------

all: $(BIN_DIR)/$(MAIN_TARGET) $(BIN_DIR)/$(DEAMON_TARGET)

# Основной бинарник
$(BIN_DIR)/$(MAIN_TARGET): $(MAIN_OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Демон
$(BIN_DIR)/$(DEAMON_TARGET): $(DEAMON_OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(DEAMON_LIBS)

# Общая компиляция .cpp → .o
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(MAIN_INCLUDES) $(DEAMON_INCLUDES) -MMD -c $< -o $@

# Подключаем зависимости
-include $(BUILD_DIR)/**/*.d

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

.PHONY: all clean
