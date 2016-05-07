all: dnsinject

dnsinject: dnsinject.c
	@echo "Generating dnsinject executable"
	gcc dnsinject.c -o dnsinject -lpcap

clean:
	@echo "Cleaning dnsinject executable"
	rm -f dnsinject
