CXX=g++
LIB_FLAGS = -lpcap 
#DEBUG = -Wall -fpermissive
DEBUG = -fpermissive
OPT = -O2
CXXFLAGS =  $(DEBUG)   $(OPT)

out=main preprocess
obj=main.o preprocess.o
all: main preprocess

main: main.cpp
	$(CXX) $(CXXFLAGS) -g -c $< $(LIB_FLAGS)
preprocess: preprocess.cpp
	$(CXX) $(CXXFLAGS) -g -c $< $(LIB_FLAGS)
$(out):$(obj)
	$(CXX) $(CXXFLAGS) -g -o $(out) $(obj) $(LIB_FLAGS)

.PHONY: clean

clean:
	rm -f  main $(obj) *~