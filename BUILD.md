# DefendEdge Endpoint DLP Agent: Build & Compilation Guide

This document provides a highly detailed, step-by-step workflow for compiling the native Go-based DLP Agent, embedding its secure application manifest, and handling cross-compilation scenarios.

---

## 🛠️ 1. Development Prerequisites

Before building the binary, verify that your development host meets the following prerequisites.

### A. Local Compiling on Windows

**Go Language Toolchain:** Install Go (v1.18 or newer) from the [Official Go Downloads Portal](https://go.dev/dl/). Ensure Go is correctly appended to your system path:
```bash
go version
```

**Resource Compiler (rsrc):** The agent requires the `rsrc` tool to bind the application manifest (`app.manifest`) directly into the final PE executable:
```bash
go install github.com/akavel/rsrc@latest
```
> **Note:** Ensure your `%USERPROFILE%\go\bin` directory is added to your environment variables (PATH) so the terminal can invoke `rsrc` directly.

### B. Cross-Compiling on Linux (e.g., Linux Mint, Ubuntu, Debian)

**Go Language Toolchain:** Install Golang via your package manager:
```bash
sudo apt update
sudo apt install golang -y
```

**Resource Compiler (rsrc):**
```bash
go install github.com/akavel/rsrc@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## 🧩 2. Embedding the Security Manifest

The `app.manifest` directs the Windows operating system on how to manage the application context. By compiling with an embedded manifest, we prevent arbitrary virtualization sandboxes and ensure the OS handles our Administrative User Account Control (UAC) prompts cleanly.

Run the resource tool inside the root directory containing `app.manifest`:
```bash
# Generate the linked Windows Resource object file
rsrc -manifest app.manifest -o rsrc.syso
```

> **⚠️ IMPORTANT**
> The Go compiler automatically detects, handles, and statically links any `.syso` file present in the current build directory. Do not rename or remove `rsrc.syso` before running the compilation command.

---

## 🚀 3. Compilation Commands

Choose the compilation configuration below that matches your targeted delivery scenario.

### Option A: Standard Build (With Debug Console)

This build type keeps the stdout console open in the background. It is highly recommended for security researchers, sandbox developers, and initial VM testing because it prints instant forensic telemetry and runtime debug outputs in real time.

**On a Windows Host:**
```bash
go build -o dlp-agent.exe main.go
```

**Cross-Compiling on a Linux Host:**
```bash
GOOS=windows GOARCH=amd64 go build -o dlp-agent.exe main.go
```

### Option B: Production Build (Hidden Background GUI)

This build configuration runs completely silently as a background service task without spawning a visual Command Prompt window. It also optimizes and strips debugging tables to significantly minimize the final payload footprint.

**On a Windows Host:**
```bash
go build -ldflags "-H=windowsgui -s -w" -o dlp-agent.exe main.go
```

**Cross-Compiling on a Linux Host:**
```bash
GOOS=windows GOARCH=amd64 go build -ldflags "-H=windowsgui -s -w" -o dlp-agent.exe main.go
```

---

## 🔍 4. Troubleshooting Compile & Runtime Flags

### 1. Alternate Data Stream (ADS) Operational Failures

**Symptom:** The console dashboard throws: `Failed to apply NTFS alternate streams.`

**Root Cause:** You are attempting to run your tests on a storage media partition formatted with FAT32, exFAT, or ReFS, which do not natively support stream forks.

**Resolution:** Ensure the directory path you are targeting (e.g., `C:\SecureData`) exists on a primary partition formatted with the NTFS filesystem.

### 2. Command Not Found: rsrc

**Symptom:** Shell returns `rsrc: command not found` or `is not recognized as an internal command`.

**Root Cause:** The Go binaries directory (`GOPATH/bin`) is missing from the terminal environment's system paths.

**Resolution:**
- **On Windows:** Add `%USERPROFILE%\go\bin` to your system's Environment Variables.
- **On Linux:** Temporarily or permanently export the path:
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### 3. Firewall Modification Rules Ignored

**Symptom:** Policy alerts trigger, but the endpoint routing path is not severed, and the host continues to reach external resources.

**Root Cause:** The agent was executed inside a low-privilege security token. Standard processes are blocked by Windows from calling local `netsh` or modifying active Defender rules.

**Resolution:** Click **Elevate** on the web dashboard to launch the secure parent-sibling process transition under a high-integrity Administrator token.
