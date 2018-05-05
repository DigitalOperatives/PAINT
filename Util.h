//_____  Util.h ____________________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: June 20, 2012
// Author		: Philip Yoon
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//__________________________________________________________________________


#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <vector>
#include <ctype.h>
#include <strsafe.h>
#include <stdio.h>
#include <conio.h>
#include <sstream>

bool isADigitWChar(wchar_t);

//User MUST delete the memory comes back
char* convertWStringHexToBin(std::wstring hex);

char hexByteToBin(std::wstring byte);

void binToHexText(char* bin, int length, char* text);

std::string wstringTostringASCII(std::wstring);

std::string getProcessPath(int pid, int maxPath, bool nameOnly);

std::vector<std::wstring> &split(const std::wstring &s, wchar_t delim, std::vector<std::wstring> &elems);
std::vector<std::wstring> split(const std::wstring &s, wchar_t delim);

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems);
std::vector<std::string> split(const std::string &s, char delim);

#endif