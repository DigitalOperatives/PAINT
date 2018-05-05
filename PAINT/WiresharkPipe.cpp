#include <string.h>
#include <io.h>

#include "WiresharkPipe.h"

int writeWiresharkHeader(int pipe, char indicator, int len)
{
	unsigned char header[4];
    header[0] = indicator;
    header[1] = (len >> 16) & 0xFF;
    header[2] = (len >> 8) & 0xFF;
    header[3] = (len >> 0) & 0xFF;

	return write(pipe, header, 4);
}

void writeWireshark(int pipe, char indicator, const char *message)
{
	if(message == NULL)
	{
		writeWiresharkHeader(pipe, indicator, 0);
		return;
	}

	int len = strlen(message) + 1;

	writeWiresharkHeader(pipe, indicator, len);
	write(pipe, message, len);
}