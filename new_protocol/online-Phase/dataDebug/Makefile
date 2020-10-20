CC = g++
CFLAGS = -std=c++14 
LDLIBS = -lgmp 

all: test.o test

$(BUILD):
	mkdir -p $(BUILD)

test.o: test.cpp
	$(CC) $(CFLAGS) -c $< -o $@

test:test.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm test.o
	rm test