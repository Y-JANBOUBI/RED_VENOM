#include "struct.h"

//================================================================================================================================================================//
//  Output
//================================================================================================================================================================//
int dll_run(const char* filename, const char* path) {
    char full_path[MAX_PATH];
    if (snprintf(full_path, sizeof(full_path), "%s\\%s", path, filename) < 0 || strlen(full_path) >= MAX_PATH) {
        fprintf(stderr, "Error: Failed to construct full path for %s\n", filename);
        return 1;
    }

    FILE* file = NULL;
    if (fopen_s(&file, full_path, "w") != 0 || file == NULL) {
        perror("Error creating file");
        return 1;
    }

    const char* batch_content =

        ":: =========================================================================================\n"
        ":: Red_Venom - Enhanced Batch Script\n"
        ":: Author: Y.JANBOUBI\n"
        ":: Description: DLL-Runner \n"
        ":: ==========================================================================================\n\n"
        "\n"
        "@echo off\n"
        "rundll32.exe run.dll,hacked\n"
        "exit /b 0\n";

    if (fputs(batch_content, file) == EOF) {
        perror("Error writing to file");
        fclose(file);
        return 1;
    }

    fclose(file);
    printf("\033[38;2;0;255;0m[+] Generated (DLL-Runner)\n\033[38;5;250m");

    return 0;
}

int generate_source(const char* payload) {
    if (!payload) {
        fprintf(stderr, "Error: Null payload\n");
        return 0;
    }

    char output_path[MAX_PATH];
    if (!GetCurrentDirectoryA(MAX_PATH, output_path)) {
        fprintf(stderr, "Error: Could not get current directory\n");
        return 0;
    }

    size_t len = strlen(output_path);
    if (len + strlen("\\Output") >= MAX_PATH) {
        fprintf(stderr, "Error: Output path too long\n");
        return 0;
    }
    if (strcat_s(output_path, sizeof(output_path), "\\Output") != 0) {
        fprintf(stderr, "Error: Failed to create tools path\n");
        return 0;
    }

    if (!CreateDirectoryA(output_path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        fprintf(stderr, "Error: Failed to create directory %s\n", output_path);
        return 0;
    }

    char payload_path[MAX_PATH];
    if (snprintf(payload_path, sizeof(payload_path), "%s\\Source.c", output_path) < 0) {
        fprintf(stderr, "Error: Failed to create payload path\n");
        return 0;
    }

    FILE* file = fopen(payload_path, "w");
    if (!file) {
        fprintf(stderr, "Error: Could not open %s for writing\n", payload_path);
        return 0;
    }

    if (fputs(payload, file) == EOF) {
        fprintf(stderr, "Error: Failed to write payload to %s\n", payload_path);
        fclose(file);
        return 0;
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "Error: Failed to close %s\n", payload_path);
        return 0;
    }

    printf("\033[38;2;255;0;0m");
    printf("[+] Running ...\n");
    printf("\033[38;2;0;255;0m");
    printf("[+] Generated Source file\n");
    printf("\033[38;5;250m");

    return 1;
}
int generate_bat(const char* format, int simple_flag) {
    if (!format) {
        fprintf(stderr, "Error: Null format\n");
        return -1;
    }

    char dir_path[MAX_PATH];
    if (!GetCurrentDirectoryA(MAX_PATH, dir_path)) {
        fprintf(stderr, "Error: Could not get current directory\n");
        return -1;
    }

    size_t len = strlen(dir_path);
    if (len + strlen("\\Output") >= MAX_PATH) {
        fprintf(stderr, "Error: Directory path too long\n");
        return -1;
    }
    if (strcat_s(dir_path, sizeof(dir_path), "\\Output") != 0) {
        fprintf(stderr, "Error: Failed to create tools path\n");
        return -1;
    }

    if (!CreateDirectoryA(dir_path, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        fprintf(stderr, "Error: Failed to create directory %s\n", dir_path);
        return -1;
    }

    char bat_path[MAX_PATH];
    if (snprintf(bat_path, sizeof(bat_path), "%s\\Compiled.bat", dir_path) < 0) {
        fprintf(stderr, "Error: Failed to create bat path\n");
        return -1;
    }

    char payload_path[MAX_PATH];
    if (snprintf(payload_path, sizeof(payload_path), "%s\\Source.c", dir_path) < 0) {
        fprintf(stderr, "Error: Failed to create payload path\n");
        return -1;
    }

    char output_file_path[MAX_PATH];
    const char* extension = _stricmp(format, "dll") == 0 ? "dll" : "exe";
    if (snprintf(output_file_path, sizeof(output_file_path), "%s\\run.%s", dir_path, extension) < 0) {
        fprintf(stderr, "Error: Failed to create output path\n");
        return -1;
    }

    FILE* bat_file = NULL;
    if (fopen_s(&bat_file, bat_path, "w") != 0 || !bat_file) {
        fprintf(stderr, "Error: Could not open %s for writing\n", bat_path);
        return -1;
    }

    const char* compile_command = NULL;
    if (_stricmp(format, "exe") == 0) {
        if (simple_flag) {
            compile_command = "gcc \"%s\" -o \"%s\" -mwindows -lws2_32 -luser32";
        }
        else {
            compile_command = "gcc \"%s\" -o \"%s\" -mwindows -lws2_32 -luser32 -lkernel32 -lgdi32 -nostdlib -nodefaultlibs -e WinMain";
        }
    }
    else if (_stricmp(format, "dll") == 0) {
        compile_command = "gcc -shared \"%s\" -o \"%s\" -lws2_32 -luser32 -lkernel32 -lgdi32 -nostdlib -nodefaultlibs -e DllMain";

    }
    else {
        fprintf(stderr, "Error: Unsupported format '%s'\n", format);
        fclose(bat_file);
        return -1;
    }

    fprintf(bat_file, ":: =========================================================================================\n");
    fprintf(bat_file, ":: Red_Venom - Enhanced Batch Script\n");
    fprintf(bat_file, ":: Author: Y.JANBOUBI\n");
    fprintf(bat_file, ":: Description: Script for clean Compiling \n");
    fprintf(bat_file, ":: ==========================================================================================\n\n");
    fprintf(bat_file, "@echo off\n");
    fprintf(bat_file, "cls\n");
    fprintf(bat_file, "chcp 65001 >nul\n");
    fprintf(bat_file, "title Red_Venom\n");
    fprintf(bat_file, "goto banner\n");
    fprintf(bat_file, ":banner\n");
    fprintf(bat_file, "echo.\n");
    fprintf(bat_file, "echo.\n");
    fprintf(bat_file, "echo		    [38;2;255;0;0m ▄████████  ▄██████▄    ▄▄▄▄███▄▄▄▄      ▄███████▄  ▄█   ▄█        ▄█  ███▄▄▄▄      ▄██████▄  [0m\n");
    fprintf(bat_file, "echo		    [38;2;218;0;0m███    ███ ███    ███ ▄██▀▀▀███▀▀▀██▄   ███    ███ ███  ███       ███  ███▀▀▀██▄   ███    ███ [0m \n");
    fprintf(bat_file, "echo		    [38;2;182;0;0m███    █▀  ███    ███ ███   ███   ███   ███    ███ ███▌ ███       ███▌ ███   ███   ███    █▀  [0m \n");
    fprintf(bat_file, "echo		    [38;2;145;0;0m███        ███    ███ ███   ███   ███   ███    ███ ███▌ ███       ███▌ ███   ███  ▄███        [0m \n");
    fprintf(bat_file, "echo		    [38;2;109;0;0m███        ███    ███ ███   ███   ███ ▀█████████▀  ███▌ ███       ███▌ ███   ███ ▀▀███ ████▄  [0m \n");
    fprintf(bat_file, "echo		    [38;2;72;0;0m███    █▄  ███    ███ ███   ███   ███   ███        ███  ███       ███  ███   ███   ███    ███ [0m \n");
    fprintf(bat_file, "echo		    [38;2;36;0;0m███    ███ ███    ███ ███   ███   ███   ███        ███  ███▌    ▄ ███  ███   ███   ███    ███ [0m \n");
    fprintf(bat_file, "echo		    [38;2;10;0;0m████████▀   ▀██████▀   ▀█   ███   █▀   ▄████▀      █▀   █████▄▄██ █▀    ▀█   █▀    ████████▀  [0m \n");
    fprintf(bat_file, "echo		    [38;2;0;0;0m                                                        ▀                                     [0m \n");
    fprintf(bat_file, "echo.\n");
    fprintf(bat_file, "echo.\n");
    fprintf(bat_file, "echo [38;2;182;0;0m[+] Compiling is running...\n");
    fprintf(bat_file, compile_command, payload_path, output_file_path);
    fprintf(bat_file, "\nif %%errorlevel%% neq 0 (\n");
    fprintf(bat_file, "  echo [!] Compilation failed\n");
    fprintf(bat_file, "  pause\n");
    fprintf(bat_file, "  exit /b 1\n");
    fprintf(bat_file, ")\n");
    fprintf(bat_file, "echo [38;2;182;0;0m[+] Compilation Finished successful [0m \n");
    fprintf(bat_file, "pause\n");
    fprintf(bat_file, "exit /b 0\n");


    if (fclose(bat_file) != 0) {
        fprintf(stderr, "Error: Failed to close %s\n", bat_path);
        return -1;
    }

    printf("\033[38;2;0;255;0m");
    printf("[+] Generated bat file\n");
    printf("\033[38;5;250m");

    if (_stricmp(format, "dll") == 0) {
        if (dll_run("DLL-Runner.bat", dir_path) != 0) {
            fprintf(stderr, "Error: Failed to generate DLL run batch file\n");
            return 1;
        }
    }

    return 0;
}
int generate_output(const char* format, const char* buffer, int simple_flag) {
    if (!format) {
        fprintf(stderr, "Error: Null format provided\n");
        return -1;
    }
    if (!buffer) {
        fprintf(stderr, "Error: Null buffer provided\n");
        return -1;
    }

    if (!generate_source(buffer)) {
        return -1;
    }

    int result = generate_bat(format, simple_flag);
    return result;
}


//================================================================================================================================================================//
// tcheck for requirements
//================================================================================================================================================================//
int create_batch_file(const char* filename) {
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error creating file");
        return 1;
    }

    const char* batch_content =
        
        ":: =========================================================================================\n"
        ":: Red_Venom - Enhanced Batch Script\n"
        ":: Author: Y.JANBOUBI\n"
        ":: Description: A powerful script for install Red_Venom requirements \n"
        ":: ==========================================================================================\n\n"
        "\n"
        "@echo off\n"
        "cls\n"
        "setlocal enabledelayedexpansion\n"
        "chcp 65001 >nul\n"
        "title Red_Venom\n"
        "\n"
        "net session >nul 2>&1\n"
        "if %errorlevel% neq 0 (\n"
        "    call :print_banner\n"
        "    call :print_Warning \"This script must be run as Administrator!\"\n"
        "    echo.\n"
        "    pause\n"
        "    exit /b 1\n"
        ")\n"
        "\n"
        "call :print_banner \n"
        "call :print_info \"Program is running...\"\n"
        "call :print_error \"Please do not close this window!\"\n"
        "\n"
        "if not exist \"%ProgramData%\\chocolatey\\choco.exe\" (\n"
        "    call :print_success \"Installing Chocolatey...\"\n"
        "    powershell -c \"Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\"|| (\n"
        "        call :print_error \"Failed to install Chocolatey!\"\n"
        "        pause\n"
        "        exit /b 1\n"
        "    )\n"
        ")\n"
        "\n"
        "call :print_info \"Installing MinGW (this may take a while)...\"\n"
        "choco install mingw -y >nul || (\n"
        "    call :print_error \"Failed to install MinGW!\"\n"
        "    pause\n"
        "    exit /b 1\n"
        ")\n"
        "\n"
        "call :print_success \"Setup completed successfully!\"\n"
        "pause\n"
        "exit /b 0\n"
        "\n"
        ":: =============================================\n"
        ":: Functions\n"
        ":: =============================================\n"
        "\n"
        ":print_banner\n"
        "echo.\n"
        "echo.\n"
        "echo            [38;2;255;0;0m   ▄████████    ▄████████     ███     ███    █▄     ▄███████▄[0m \n"
        "echo            [38;2;218;0;0m  ███    ███   ███    ███ ▀█████████▄ ███    ███   ███    ███[0m \n"
        "echo            [38;2;182;0;0m  ███    █▀    ███    █▀     ▀███▀▀██ ███    ███   ███    ███[0m \n"
        "echo            [38;2;145;0;0m  ███         ▄███▄▄▄         ███   ▀ ███    ███   ███    ███[0m \n"
        "echo            [38;2;72;0;0m▀███████████ ▀▀███▀▀▀         ███     ███    ███ ▀█████████▀ [0m \n"
        "echo            [38;2;36;0;0m         ███   ███    █▄      ███     ███    ███   ███       [0m \n"
        "echo            [38;2;10;0;0m   ▄█    ███   ███    ███     ███     ███    ███   ███       [0m \n"
        "echo            [38;2;0;0;0m ▄████████▀    ██████████    ▄████▀   ████████▀   ▄████▀   [0m \n"
        "echo.\n"
        "goto :eof\n"
        "\n"
        ":print_info\n"
        "echo [38;2;0;255;0m[Info]: %~1[0m\n"
        "goto :eof\n"
        "\n"
        ":print_success\n"
        "echo [38;2;0;255;0m[Success]: %~1[0m\n"
        "goto :eof\n"
        "\n"
        ":print_error\n"
        "echo [38;2;218;0;0m[Warning]: %~1 [0m\n"
        "goto :eof\n"
        "\n"
        ":print_Warning\n"
        "echo [38;2;218;0;0m[Info]: %~1 [0m\n"
        "goto :eof\n";


    if (fputs(batch_content, file) == EOF) {
        perror("Error writing to file");
        fclose(file);
        return 1;
    }

    fclose(file);
    return 0;
}
int check_mingw_installed(IN char* argv_0) {

    int result = system("gcc --version > nul 2>&1");

    if (result != 0) {
        print_usage();
        printf("\033[38;2;255;0;0m");
        printf("[!] MinGW is not installed or gcc is not in the system PATH.\n");
        printf("[+] You need to install MinGW.\n");
        create_batch_file("setup.bat");
        printf("\033[38;2;0;255;0m");
        printf("[+] Run setup.bat and restart (%s)\n", argv_0);
        printf("\033[38;2;255;0;0m");
        printf("[!] Press <enter> to exit");
        printf("\033[38;5;250m");
        getchar();
        return 1;
    }
    return 0;
}


