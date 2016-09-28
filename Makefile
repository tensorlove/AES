CC = g++

CFLAGS = -Wall -O3 -msse4 -m64
OBJS = aes_ref.o aes_v1.o aux.o aes_test.o
TARGET = aes_test

.SUFFIXES: .cpp .o

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean:
	rm -rf $(OBJS) $(TARGET)