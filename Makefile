CC = gcc

CFLAGS = -Wall -Wextra -Werror -pedantic -std=c11 -g -fsanitize=address

TARGET = minikart

SRC = minikart.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)