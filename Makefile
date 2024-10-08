
# Compiler
CXX = g++
CXXFLAGS = -std=c++11 -pthread

# Targets
TARGET_SERVER = tsamgroup1
TARGET_CLIENT = client

# Source files
SRC_SERVER = server.cpp
SRC_CLIENT = client.cpp

# Default target
all: $(TARGET_SERVER) $(TARGET_CLIENT)

# Compile server
$(TARGET_SERVER): $(SRC_SERVER)
	$(CXX) $(CXXFLAGS) -o $(TARGET_SERVER) $(SRC_SERVER)

# Compile client
$(TARGET_CLIENT): $(SRC_CLIENT)
	$(CXX) $(CXXFLAGS) -o $(TARGET_CLIENT) $(SRC_CLIENT)

# Clean up build files
clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT)