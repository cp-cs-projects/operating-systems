CC = gcc
CFLAGS = `pkg-config fuse --cflags` -Wall -D_FILE_OFFSET_BITS=64
LDFLAGS = `pkg-config fuse --libs` -lcrypto -lssl

TARGET = mirror_fs
SOURCES = mirror_fs.c


all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
	make