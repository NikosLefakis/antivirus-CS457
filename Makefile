antivirus:  antivirus.c src/scan.c src/inspect.c src/monitor.c src/slice-unlock.c include/antivirus.h
	gcc -o antivirus antivirus.c src/scan.c src/inspect.c src/monitor.c src/slice-unlock.c -lcrypto -lcurl

all: antivirus

clean:
	rm -f antivirus