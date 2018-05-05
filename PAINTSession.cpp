//_____  PAINTSession.cpp __________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: June 20, 2012
// Author		: Philip Yoon
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//__________________________________________________________________________


#include "PAINTSession.h"
#include "Util.h"

//Creating the static variable
PAINTSession *PAINTSession::m_me;

PAINTSession* PAINTSession::getInstance()
{
	if (m_me)
		return m_me;

	m_me = new PAINTSession();

	return m_me;
}

PAINTSession::PAINTSession()
{
	m_me = 0; 
	m_outputCSVFile = 0; 
	m_consoleOutputFile;

	m_formattedStringLen = 1024*1024;
	m_formattedString = new WCHAR[m_formattedStringLen];

	/*
	* I should really make this a run-time option 
	* so I won't have to recompile things
	*
	errno_t err;
	err = fopen_s(&m_consoleOutputFile, "consoleOutput.txt", "w");
	if (err != 0)
	{
		wprintf(L"Error: the file 'consoleOutput.txt' was not opened.\n");
	}

	err = fopen_s(&m_outputCSVFile, "PAINTOutput.csv", "w");
	if(err != 0)
	{
		wprintf(L"Error: the file 'PAINTOutput.csv' was not opened.\n");
	}
	*/
	m_pcapFile.open("PAINTOutput.pcap");

}

PAINTSession::~PAINTSession()
{
	delete [] m_formattedString;
};


void PAINTSession::storePID(std::string TCB, int PID, std::string processName)
{
	PIDName n;
	n.PID = PID;
	n.processName = processName;

	m_TCBToPIDName[TCB] = n;
}

void PAINTSession::deletePID(std::string TCB)
{
	m_TCBToPIDName.erase(TCB);
}

PAINTSession::PIDName PAINTSession::getPID(std::string TCB)
{
	PIDName n;
	n.PID = -1;

	if (m_TCBToPIDName.find(TCB) == m_TCBToPIDName.end())
		return n;
	
	return m_TCBToPIDName[TCB];
}

void PAINTSession::storeActID(std::string actID, int PID, std::string processName)
{
	//DEBUG
	//CSVPrintAndWrite("Storing, %s, %s\n", actID.c_str(), processName.c_str());

	PIDName n;
	n.PID = PID;
	n.processName = processName;

	m_ActIDToPIDName[actID] = n;
}

void PAINTSession::deleteActID(std::string actID)
{
	m_ActIDToPIDName.erase(actID);
}

void PAINTSession::emptyActIDMap()
{
	m_ActIDToPIDName.empty();
}

PAINTSession::PIDName PAINTSession::getActID(std::string actID, int size)
{
	PIDName n;
	n.PID = -1;

	if (m_ActIDToPIDName.find(actID) == m_ActIDToPIDName.end())
		return n;

	return m_ActIDToPIDName[actID];
}

int PAINTSession::printAndWrite(const char* format, ... )
{	
	//DEBUG
	return 0;

	m_formattedString[0] = 0;

	va_list args;
	va_start(args,format);
	//vprintf(format,args);
	vfprintf_s(m_consoleOutputFile, format, args);
	va_end(args);
	
	return 0;
}

WCHAR* PAINTSession::wprintAndWrite(const wchar_t* format, ... )
{
	m_formattedString[0] = 0;

	va_list args;
	va_start(args,format);
	//vwprintf(format,args);
	//vfwprintf_s(m_consoleOutputFile, format, args);
	vswprintf_s(m_formattedString, m_formattedStringLen, format, args);
	va_end(args);
	
	return m_formattedString;
}

int PAINTSession::CSVPrintAndWrite(const char* format, ... )
{	
	//DEBUG
	return 0;

	m_formattedString[0] = 0;

	va_list args;
	va_start(args,format);

	//Writing out to the console
	//vprintf(format,args);
	
	vfprintf_s(m_outputCSVFile, format, args);
	va_end(args);
	

	return 0;
}

WCHAR* PAINTSession::CSVWPrintAndWrite(const wchar_t* format, ... )
{
	//DEBUG
	return 0;

	m_formattedString[0] = 0;
	
	va_list args;
	va_start(args,format);
	
	//Writing out to the console
	vwprintf(format,args);
	
	vfwprintf_s(m_outputCSVFile, format, args);
	vswprintf_s(m_formattedString, m_formattedStringLen, format, args);
	va_end(args);
	
	return m_formattedString;
}

void PAINTSession::writePacket(char* fragment, int size, int PID, std::string processName, unsigned long long currentTimeMicroSeconds)
{
	m_pcapFile.writePacket(size, fragment, PID, processName, currentTimeMicroSeconds);
}