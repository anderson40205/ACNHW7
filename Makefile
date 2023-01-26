all:main fill_packet
	gcc main.o fill_packet.o -lpthread -o ipscanner -lpcap
main:main.o 
	gcc -c main.c -o main.o 
fill_packet:fill_packet.o
	gcc -c fill_packet.c -o fill_packet.o 
clean:
	rm *.o ipscanner