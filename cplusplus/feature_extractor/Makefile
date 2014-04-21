CXX=g++
LIB_FLAGS = -lpcap 
#DEBUG = -Wall -fpermissive
DEBUG = -fpermissive
OPT = -O2
CXXFLAGS =  $(DEBUG)   $(OPT)

out=main
obj=main.o
all: main

main: main.cpp
	$(CXX) $(CXXFLAGS) -g -c $< $(LIB_FLAGS)
$(out):$(obj)
	$(CXX) $(CXXFLAGS) -g -o $(out) $(obj) $(LIB_FLAGS)

.PHONY: clean

clean:
	rm -f  main $(obj) *~