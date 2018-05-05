//_____  Util.cpp _________________________________________________________
//
// Module		: PAINT
// Description	: Process Attribution in Network Traffic
// Date			: March 6, 2012
// Author		: Philip Yoon and Mike Myers
// Company		: Digital Operatives LLC
// Project		: Work performed under DARPA Cyber Fast Track
//
// File Name    : Util.cpp
// File Purpose : (Mostly) string utility functions 
//__________________________________________________________________________


#include "Util.h"

std::vector<std::wstring> &split(const std::wstring &s, wchar_t delim, std::vector<std::wstring> &elems) {
    std::wstringstream ss(s);
    std::wstring item;
    while(std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    return split(s, delim, elems);
}

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while(std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

std::vector<std::wstring> split(const std::wstring &s, wchar_t delim) {
    std::vector<std::wstring> elems;
    return split(s, delim, elems);
}

bool isADigitWChar(wchar_t wchar)
{
	switch(wchar)
	{
	case L'0':
	case L'1':
	case L'2':
	case L'3':
	case L'4':
	case L'5':
	case L'6':
	case L'7':
	case L'8':
	case L'9':
		return true;
	};

	return false;
}

char* convertWStringHexToBin(std::wstring hex)
{
	int binLength = hex.size() / 2;
	char* bin = new char[binLength];

	for (int a = 0; a < binLength; a++)
	{
		std::wstring byte = hex.substr(a*2, 2);
		bin[a] = hexByteToBin(byte);
	}

	return bin;
}

char hexByteToBin(std::wstring byte)
{
	char toReturn = 0;

	if (byte.size() != 2)
		return toReturn;

	if (byte[1] >= L'0' && byte[1] <= L'9')
		toReturn = byte[1] - L'0';
	else if (byte[1] >= L'A' && byte[1] <= L'F')
		toReturn = byte[1] - L'A' + 10;
	else if (byte[1] >= L'a' && byte[1] <= L'f')
		toReturn = byte[1] - L'a' + 10;

	if (byte[0] >= L'0' && byte[0] <= L'9')
		toReturn += (byte[0] - L'0') << 4;
	else if (byte[0] >= L'A' && byte[0] <= L'F')
		toReturn += (byte[0] - L'A' + 10) << 4;
	else if (byte[0] >= L'a' && byte[0] <= L'f')
		toReturn += (byte[0] - L'a' + 10) << 4;

	return toReturn;
}

void binToHexText(char* bin, int length, char* text)
{
	for (int a = 0; a < length; a++)
	{
		sprintf_s(text+a*2, 3, "%.2X", (unsigned char)bin[a]);
	}
}

std::string wstringTostringASCII(std::wstring wstr)
{
	std::string toReturn;
	for (int a = 0; a < wstr.length(); a++)
	{
		wchar_t wc = wstr[a];
		short wcs = *(short*)&wc;
		//wcs = wcs >> 8;
		char c = (char)wcs;
		toReturn.push_back(c);
	}

	return toReturn;
}