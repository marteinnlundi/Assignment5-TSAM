# Compiler
CXX = g++
CXXFLAGS = -std=c++11 -pthread

# Targets
TARGET_SERVER = tsamgroup1
TARGET_CLIENT = client

# Source files for server
SRC_SERVER = main.cpp server.cpp message_handler.cpp logging.cpp security.cpp utilities.cpp

# Object files for server (derived from the source files)
OBJ_SERVER = $(SRC_SERVER:.cpp=.o)

# Source file for client
SRC_CLIENT = client.cpp

# Object files for client (if needed)
OBJ_CLIENT = $(SRC_CLIENT:.cpp=.o)

# Default target
all: $(TARGET_SERVER) $(TARGET_CLIENT)

# Compile server
$(TARGET_SERVER): $(OBJ_SERVER)
	$(CXX) $(CXXFLAGS) -o $(TARGET_SERVER) $(OBJ_SERVER)

# Compile client
$(TARGET_CLIENT): $(SRC_CLIENT)
	$(CXX) $(CXXFLAGS) -o $(TARGET_CLIENT) $(SRC_CLIENT)

# Pattern rule to compile each source file into an object file
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJ_SERVER) $(OBJ_CLIENT) $(TARGET_SERVER) $(TARGET_CLIENT)
