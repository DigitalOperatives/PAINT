#include <stdio.h>
#include <stdlib.h>
#include <string>

using namespace std;

static int packetNumber = 0;
static FILE *processFile;

void writeProcess(int PID, string processName)
{
	int processNameLength = processName.size();
	fwrite((void*)&packetNumber, sizeof(int), 1, processFile);
	fwrite((void*)&PID, sizeof(int), 1, processFile);
	fwrite((void*)&processNameLength, sizeof(int), 1, processFile);
	if (processNameLength > 0)
		fwrite((void*)processName.c_str(), sizeof(char), processNameLength, processFile);

	packetNumber++;
}

int main()
{
	processFile = _fsopen("SkypeIRC.cap.process", "wb", _SH_DENYNO);
	if(processFile == 0)
	{
		printf("Error: the file '%s' was not opened.\n", "SkypeIRC.cap.process");
	}
	
	writeProcess(1546, "mirc.exe");
	writeProcess(1546, "mirc.exe");
	writeProcess(1546, "mirc.exe");
	writeProcess(1546, "mirc.exe");

	for (int a = 0; a < 10; a++)
		writeProcess(8762, "svchost.exe");

	writeProcess(1546, "mirc.exe");
	writeProcess(1546, "mirc.exe");
	writeProcess(1546, "mirc.exe");
	writeProcess(1546, "mirc.exe");
	writeProcess(1546, "mirc.exe");
	writeProcess(1546, "mirc.exe");

	writeProcess(1190, "notsobenign.exe");
	writeProcess(8762, "svchost.exe");

	fclose(processFile);

	return 0;
}