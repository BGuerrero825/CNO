CC="gcc"
CFLAGS="-g"

StegoLSB: StegoLSB.cpp bmp_lsb.cpp LSB.cpp

decode: StegoLSB
	./StegoLSB.exe x images/output.bmp images/output.jpg

encode: StegoLSB
	./StegoLSB.exe s images/sample.bmp images/secret.jpg images/output.bmp
