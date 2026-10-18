
CFLAGS=-DHASH_DEBUG -O2 -Wall
OBJ=hash.o ../gap.o htest.o

hash.o: ../hash.c
	$(CC) $(CFLAGS) -c -o $@ $<

htest: $(OBJ)
	$(CC) -o htest $(OBJ)

