#include "pch.h"

BOOL is_injection(Data* data)
{
	if (data->fcts.find("CreateFileA") != std::string::npos)
	{
		return true;
	}

	return false;
}