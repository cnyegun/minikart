CC = gcc

CFLAGS = -Wall -Wextra -Werror -std=c23 -g -fsanitize=address

TARGET = minikart

SRC = minikart.c art.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)
