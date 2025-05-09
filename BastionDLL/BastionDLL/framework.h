#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <winternl.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <map>
#include <fstream>
#include <vector>

enum FLAGS {
    TERMINATE = 0,
    SUSPEND
};

class Data {
public:
    std::string fcts;
    std::map<std::string, std::string> mp;
    std::fstream file;
    char flags[2];

    Data()
    {
        file.open("C:\\Users\\bucur\\source\\repos\\BastionEDR\\BastionDLL\\SactumDllEDR_log.txt", std::ios::in | std::ios::out | std::ios::app);
        if (!file.is_open())
        {
            printf("Could not open log file!\n");
            exit(1);
        }
        file << "Injected in new Process!\n";
        memset(flags, 0, sizeof(flags));
    }
};

extern Data data;