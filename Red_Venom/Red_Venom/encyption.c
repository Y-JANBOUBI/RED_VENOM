#include "struct.h"
#pragma comment(lib, "Advapi32.lib")

//===================================================================================================//
// heder
//===================================================================================================//
typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;
typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);

//===================================================================================================//
// RC4
//===================================================================================================//
VOID RC4GenerateProtectedKey(IN BYTE HintByte, IN SIZE_T sKey, OUT PBYTE* ppOriginalKey, OUT PBYTE* ppProtectedKey) {
   
    srand((unsigned int)time(NULL) / 3);
    
    BYTE b;
    PBYTE pKey;
    PBYTE pProtectedKey;
    b = rand() % 0xFF;
    pKey = (PBYTE)malloc(sKey);
    pProtectedKey = (PBYTE)malloc(sKey);

    if (!pKey || !pProtectedKey) {
        if (pKey) free(pKey);
        if (pProtectedKey) free(pProtectedKey);
        return;
    }

    srand((unsigned int)time(NULL) * 2);

    pKey[0] = HintByte;

    for (int i = 1; i < sKey; i++) {
        pKey[i] = (BYTE)rand() % 0xFF;
    }

    for (int i = 0; i < sKey; i++) {
        pProtectedKey[i] = (BYTE)((pKey[i] + i) ^ b);
    }

    *ppProtectedKey = pProtectedKey;
    *ppOriginalKey = pKey;
}
BOOL Rc4Encrypt(IN PBYTE pRc4Key, IN DWORD dwRc4KeySize, IN OUT PBYTE pPayloadData, IN DWORD sPayloadSize) {
    NTSTATUS STATUS = 0;
    USTRING Key = { .Buffer = pRc4Key, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize };
    USTRING Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };

    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
    if (!SystemFunction032) {
        printf("[!] GetProcAddress for SystemFunction032 FAILED With Error: %d\n", GetLastError());
        return FALSE;
    }
      
    STATUS = SystemFunction032(&Img, &Key);
    if (STATUS != 0) {
        printf("[!] SystemFunction032 Encryption FAILED With Error: 0x%0.8X\n", STATUS);
        return FALSE;
    }
    return TRUE;
}


//===================================================================================================//
// Read file.bin 
//===================================================================================================//
BOOL OpenPayloadFile(const char* fileName, PBYTE* ppPayloadData, PDWORD pPayloadSize) {
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFileA FAILED With Error: %d\n", GetLastError());
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[!] GetFileSize FAILED With Error: %d\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    PBYTE payload = (PBYTE)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!payload) {
        printf("[!] HeapAlloc for payload FAILED\n");
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, payload, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] ReadFile FAILED With Error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, payload);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    *ppPayloadData = payload;
    *pPayloadSize = fileSize;
    return TRUE;
}
VOID creatHexArray(char* output, PBYTE data, DWORD size, size_t output_size) {
    size_t offset = 0;

    for (DWORD i = 0; i < size && offset < output_size - 20; i++) {
        offset += sprintf_s(output + offset, output_size - offset, "0x%02X", data[i]);
        if (i < size - 1) {
            offset += sprintf_s(output + offset, output_size - offset, ", ");
        }
        if ((i + 1) % 16 == 0 && i < size - 1) {
            offset += sprintf_s(output + offset, output_size - offset, "\n    ");
        }
    }
}

//===================================================================================================//
// XOR 
//===================================================================================================//
VOID obf_HexArray(char* output, PBYTE data, DWORD size, size_t output_size) {
    size_t offset = 0;
    for (DWORD i = 0; i < size && offset < output_size - 4; i++) {
        offset += sprintf_s(output + offset, output_size - offset, "0x%02X", data[i]);
        if (i < size - 1) {
            offset += sprintf_s(output + offset, output_size - offset, ", ");
        }
    }
}
VOID xor (char* data, size_t data_len, const char* key, size_t key_len) {
    for (size_t i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key[i % key_len];
    }
}
char* generate_random_string_key() {


#define XOR_KEY_SIZE 20

    static const char alphanum[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "123456789";

    // Allocate memory
    char* buffer = (char*)malloc(XOR_KEY_SIZE);
    if (buffer == NULL) {
        return NULL; 
    }

    // Seed random number generator (should be done once, typically at program start)
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    // Generate random key
    for (int i = 0; i < XOR_KEY_SIZE - 1; i++) {
        buffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    buffer[XOR_KEY_SIZE - 1] = '\0';
    return buffer;
}
char* obf(const char* text, const char* key) {
    size_t input_len = strlen(text);
    char* cipher_text = (char*)malloc(input_len + 1);
    if (!cipher_text) return NULL;

    // Copy input to cipher_text and XOR
    strcpy_s(cipher_text, input_len + 1, text);
    xor (cipher_text, input_len, key, strlen(key));

    // Convert to hex string
    char* hex_output = (char*)malloc(input_len * 5 + 1); 
    if (!hex_output) {
        free(cipher_text);
        return NULL;
    }
    obf_HexArray(hex_output, (PBYTE)cipher_text, input_len, input_len * 10 + 1);
    free(cipher_text);
    return hex_output;
}

//===================================================================================================//
// generate random byte 
//===================================================================================================//
char* generate_random_byte_key() {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    unsigned char random_byte = rand() % 256;

    char* buffer = (char*)malloc(5);
    if (!buffer) {
        return NULL;
    }

    sprintf_s(buffer, 5, "0x%02X", random_byte);

    return buffer;
}



