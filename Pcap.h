//_____  Pcap.h ____________________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: June 20, 2012
// Author		: Philip Yoon
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//__________________________________________________________________________


#ifndef PCAP_H
#define PCAP_H

#include <stdio.h>
#include <conio.h>
#include <windows.h>
#include <string>

#define MAX_CAPTURE_SIZE 65535

struct PCAPHeader {
		unsigned long magicNumber;
		unsigned short majorVersion;
		unsigned short minorVersion;
		long  timeZone;
		unsigned long accuracy;
		unsigned long maxLength;
		unsigned long dataLinkType;
};

struct PCAPRecordHeader{
		unsigned long timeStampSecs;
		unsigned long timeStampMicroSecs;
		unsigned long includeLength;
		unsigned long actualLength;
};

#pragma pack(push, 1)
struct _802_11_Header
{
	unsigned char ver_type_subtype;
	unsigned char flags;
	unsigned char duration[2];
	unsigned char Add1[6];
	unsigned char Add2[6];
	unsigned char Add3[6];
	unsigned char seqCtrl[2];
	//unsigned char Add4[6]; //Add4 is only used in mesh mode. We do not support it.
};
#pragma pack(pop)

class Pcap
{
public:
	Pcap();
	~Pcap();
	int open(const char* fileName);
	void writePacket(int length, char* data, int PID, std::string processName, unsigned long long currentTimeMicroSeconds);

	static void flushPacket();
	static unsigned long long getCurrentTimeInMicroSeconds();

	static void forceWireless(bool force){bForceWireless = force;};

private:
	static FILE *pcapFile;
	static FILE *processFile;
	static unsigned long long startTime;
	static unsigned int numPacketsToFlush;
	static bool bForceWireless;

	unsigned int packetNumber;
};

#endif