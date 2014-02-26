CXX=g++
LIB_FLAGS = -lpcap 
DEBUG = -Wall
OPT = -O2
CXXFLAGS =  $(DEBUG)   $(OPT)

main:pcap_throughput.c
	$(CXX) $(CXXFLAGS) -o $@  $< $(LIB_FLAGS)
.PHONY: clean

clean:
	rm -f  main $(obj) *~