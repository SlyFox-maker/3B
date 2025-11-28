CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17
TARGET = nfqws_test
LIBS = -lnetfilter_queue

$(TARGET): nfqws_test.cpp
	$(CXX) $(CXXFLAGS) -o $(TARGET) nfqws_test.cpp $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: clean