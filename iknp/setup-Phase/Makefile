CC = g++

CFLAGS = -std=c++14 -pthread
LDLIBS = -lgmp -llibOTe -lcryptoTools  -lboost_system -lboost_thread -lrelic_s
BUILD = build

SRC = aliceSetup.cpp bobSetup.cpp

OBJPATHS = $(patsubst %.cpp,$(BUILD)/%.o, $(SRC))

all: $(BUILD) $(OBJPATHS) aliceSetup bobSetup

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

aliceSetup:$(BUILD)/aliceSetup.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

bobSetup:$(BUILD)/bobSetup.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -rf $(BUILD) *~
	rm aliceSetup
	rm bobSetup