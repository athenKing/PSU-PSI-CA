CC = g++

CFLAGS = -std=c++14 -pthread

LDLIBS = -lgmp -lgmpxx -llibOTe -lcryptoTools  -lboost_system -lboost_thread -lrelic_s

BUILD = build

SRC = alice.cpp bob.cpp cJSON.cpp functions.cpp murmur3.cpp

OBJPATHS = $(patsubst %.cpp,$(BUILD)/%.o, $(SRC))

all: $(BUILD) $(OBJPATHS) alice bob

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

alice:$(BUILD)/alice.o $(BUILD)/cJSON.o $(BUILD)/bloom.o $(BUILD)/functions.o $(BUILD)/murmur3.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDPATH) $(LDLIBS)

bob:$(BUILD)/bob.o $(BUILD)/cJSON.o $(BUILD)/bloom.o $(BUILD)/functions.o $(BUILD)/murmur3.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDPATH) $(LDLIBS)

clean:
	rm -rf $(BUILD) *~
	rm alice
	rm bob