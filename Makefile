CLANG ?= clang
CXX = g++
CFLAGS ?= -g -O2 -Wall
MCXXFLAGS := -g -std=c++2a -Wall -O2 -DREC_ONLY_HOST -Ilib/

BPFTOOL ?= /usr/lib/linux-hwe-6.8-tools-6.8.0-100/bpftool
LIBBPF_DIR = /home/bigdatalab/tchoe/libbpf/install

all: dlogger eaudit

kdarshan.bpf.o: dlogger.bpf.c kdarshan.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -I$(LIBBPF_DIR)/usr/include -c dlogger.bpf.c -o kdarshan.bpf.o

kdarshan.skel.h: kdarshan.bpf.o
	$(BPFTOOL) gen skeleton kdarshan.bpf.o > kdarshan.skel.h

eauditd.o: eauditd.C
	$(CXX) $(MCXXFLAGS) -c eauditd.C -o eauditd.o

eParser.o: eParser.C
	$(CXX) $(MCXXFLAGS) -c eParser.C -o eParser.o

prthelper.o: prthelper.C
	$(CXX) $(MCXXFLAGS) -c prthelper.C -o prthelper.o

eConsumer.o: eConsumer.C
	$(CXX) $(MCXXFLAGS) -c eConsumer.C -o eConsumer.o

ePrinter.o: ePrinter.C
	$(CXX) $(MCXXFLAGS) -c ePrinter.C -o ePrinter.o

eRecorder.o: eRecorder.C
	$(CXX) $(MCXXFLAGS) -c eRecorder.C -o eRecorder.o

RecOnlyHost.o: RecOnlyHost.C
	$(CXX) $(MCXXFLAGS) -c RecOnlyHost.C -o RecOnlyHost.o

dlogger: dlogger.C kdarshan.skel.h eauditd.o eParser.o prthelper.o eConsumer.o ePrinter.o eRecorder.o RecOnlyHost.o
	$(CXX) $(MCXXFLAGS) -I$(LIBBPF_DIR)/usr/include dlogger.C \
		eauditd.o eParser.o prthelper.o eConsumer.o ePrinter.o eRecorder.o RecOnlyHost.o \
		$(LIBBPF_DIR)/usr/lib64/libbpf.a -lbcc -lelf -lz -lpthread -o dlogger

eaudit: eaudit.C eParser.o prthelper.o eConsumer.o ePrinter.o eRecorder.o RecOnlyHost.o
	$(CXX) $(MCXXFLAGS) eaudit.C \
		eParser.o prthelper.o eConsumer.o ePrinter.o eRecorder.o RecOnlyHost.o \
		-lelf -lz -lpthread -o eaudit

clean:
	rm -f dlogger eaudit kdarshan.bpf.o kdarshan.skel.h *.o *.bin *.csv *.txt

.PHONY: all clean
