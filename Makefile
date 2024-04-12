CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap

SRC = wireview.c
OBJ = $(SRC:.c=.o)
EXEC = wireview

.PHONY: all clean

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXEC) $(OBJ)
