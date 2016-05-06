all: dnsinject

mydump: dnsinject.c
	@echo "Generating dnsinject executable"
	gcc -w dnsinject.c -lpcap -o dnsinject

clean:
	@echo "Cleaning dnsinject executable"
	rm -f dnsinject
