CC = gcc

CFLAGS = -std=c23 -g -fsanitize=address

TARGET = minikart

SRC = minikart.c art.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
