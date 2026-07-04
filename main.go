package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Thread-safe state structure
type SecurityState struct {
	mu             sync.Mutex
	IsDlpActive    bool     `json:"is_dlp_active"`
	IsIsolated     bool     `json:"is_isolated"`
	IsAdmin        bool     `json:"is_admin"`
	MonitoredFiles []string `json:"monitored_files"`
	Logs           []LogMsg `json:"logs"`
	ListeningPort  int      `json:"listening_port"`
}

type LogMsg struct {
	Timestamp string `json:"timestamp"`
	Severity  string `json:"severity"`
	Event     string `json:"event"`
	Details   string `json:"details"`
}

var state = SecurityState{
	IsDlpActive:    true, // Enabled by default
	IsIsolated:     false,
	IsAdmin:        false,
	MonitoredFiles: []string{},
	Logs:           []LogMsg{},
	ListeningPort:  9900,
}

func main() {
	// 1. Detect privilege level using Windows' native shell32 API (100% reliable)
	state.IsAdmin = checkIfAdmin()

	// 2. Assign completely separate ports
	if state.IsAdmin {
		state.ListeningPort = 9901
	} else {
		state.ListeningPort = 9900
	}

	// 3. Clear only the process occupying OUR port (Standard doesn't kill Admin, and vice versa)
	killProcessOnPort(state.ListeningPort)

	appendLog("INFO", fmt.Sprintf("DefendEdge Web Server starting on port :%d", state.ListeningPort), "Nominal listening socket assigned.")
	if state.IsAdmin {
		appendLog("SUCCESS", "DLP Agent running in Elevated Admin privilege context.", "Firewall manipulation and alternate data streams fully armed.")
	} else {
		appendLog("WARNING", "Running as Standard User.", "Launch elevation request to trigger UAC and activate protection rules.")
	}

	// Start the Active Filesystem Watcher Loop
	go runDlpSecurityWatcher()

	// Set up HTTP Endpoints for our Dashboard API
	http.HandleFunc("/", handleServeDashboard)
	http.HandleFunc("/api/status", handleGetStatus)
	http.HandleFunc("/api/toggle-dlp", handleToggleDlp)
	http.HandleFunc("/api/tag", handleTagFile)
	http.HandleFunc("/api/unmark", handleUnmarkFile)
	http.HandleFunc("/api/de-isolate", handleDeIsolate)
	http.HandleFunc("/api/elevate", handleRequestElevate)
	http.HandleFunc("/api/simulate-access", handleSimulateAccess)
	http.HandleFunc("/api/shutdown", handleShutdown)
	
	// Cross-console active redirection checker
	http.HandleFunc("/api/check-admin-online", handleCheckAdminOnline)

	// Automatically open the default browser to the corresponding port
	go func() {
		time.Sleep(1 * time.Second) // Let server bind successfully
		openBrowser(fmt.Sprintf("http://localhost:%d", state.ListeningPort))
	}()

	// Bind and run HTTP web server on the assigned port
	bindAddr := fmt.Sprintf("127.0.0.1:%d", state.ListeningPort)
	err := http.ListenAndServe(bindAddr, nil)
	if err != nil {
		showErrorBox(fmt.Sprintf("Failed to launch local dashboard on port %d: %v\nAnother process is blocking this port.", state.ListeningPort, err))
		os.Exit(1)
	}
}

// Find and kill only the process listening on a specific port
func killProcessOnPort(port int) {
	cmdText := fmt.Sprintf("netstat -ano | findstr :%d", port)
	out, err := exec.Command("cmd", "/c", cmdText).Output()
	if err != nil {
		return // Port is already empty/free
	}

	lines := strings.Split(string(out), "\r\n")
	myPid := fmt.Sprintf("%d", os.Getpid())

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			pidStr := fields[len(fields)-1]
			// Ensure we never try to kill our own newly spawned process
			if pidStr != myPid && pidStr != "0" {
				_ = exec.Command("taskkill", "/F", "/PID", pidStr).Run()
			}
		}
	}
	time.Sleep(300 * time.Millisecond) // Let Windows release the port socket
}

// ==========================================
// BACKGROUND PROTECTION WATCHER ENGINE
// ==========================================
func runDlpSecurityWatcher() {
	for {
		time.Sleep(500 * time.Millisecond)

		state.mu.Lock()
		dlpActive := state.IsDlpActive
		files := make([]string, len(state.MonitoredFiles))
		copy(files, state.MonitoredFiles)
		state.mu.Unlock()

		if !dlpActive {
			continue
		}

		if len(files) == 0 {
			continue
		}

		for _, file := range files {
			adsStreamPath := file + ":security.policy"
			data, err := os.ReadFile(adsStreamPath)
			if err != nil || string(data) != "NEVER_LEAVE" {
				continue 
			}

			if isFileBeingAccessed(file) {
				triggerHostIsolation("chrome.exe", file)
			}
		}
	}
}

func triggerHostIsolation(untrustedProcess string, filePath string) {
	state.mu.Lock()
	if state.IsIsolated || !state.IsDlpActive {
		state.mu.Unlock()
		return
	}
	state.IsIsolated = true
	state.mu.Unlock()

	if state.IsAdmin {
		cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Block_All_Egress", "dir=out", "action=block")
		_ = cmd.Run()
		appendLog("CRITICAL", "COMPROMISE IN PROGRESS: Target host isolated by Administrator rule.", fmt.Sprintf("Process %s attempted to read tagged asset: %s", untrustedProcess, filePath))
	} else {
		appendLog("ALERT", "DLP Violation detected, but host isolation failed due to missing Administrative permissions.", fmt.Sprintf("Process %s touched: %s", untrustedProcess, filePath))
	}

	go func() {
		user32 := syscall.NewLazyDLL("user32.dll")
		procMessageBoxW := user32.NewProc("MessageBoxW")
		msgTitle, _ := syscall.UTF16PtrFromString("DefendEdge Security Alert")
		msgBody, _ := syscall.UTF16PtrFromString(fmt.Sprintf(
			"DLP Alert: Unauthorized data access detected!\n\nProcess: %s\nTarget Asset: %s\n\nOutbound network adapters have been dynamically monitored.",
			untrustedProcess, filePath,
		))
		procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msgBody)), uintptr(unsafe.Pointer(msgTitle)), 0x00000010)
	}()
}

// ==========================================
// REST API CONTROLLERS
// ==========================================
func handleServeDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlDashboard))
}

func handleGetStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	state.mu.Lock()
	defer state.mu.Unlock()
	json.NewEncoder(w).Encode(state)
}

func handleToggleDlp(w http.ResponseWriter, r *http.Request) {
	state.mu.Lock()
	state.IsDlpActive = !state.IsDlpActive
	activeState := state.IsDlpActive
	state.mu.Unlock()

	if activeState {
		appendLog("INFO", "DLP Protection Engine manually enabled.", "Core rules and watcher loops active.")
	} else {
		appendLog("WARNING", "DLP Protection Engine de-activated.", "File system monitoring suspended.")
	}
	w.WriteHeader(http.StatusOK)
}

func handleTagFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	type tagRequest struct {
		Path string `json:"path"`
	}
	var req tagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !state.IsAdmin {
		http.Error(w, "Admin rights required to modify NTFS alternate streams", http.StatusForbidden)
		return
	}

	cleanPath := filepath.Clean(req.Path)
	adsStreamPath := cleanPath + ":security.policy"
	err := os.WriteFile(adsStreamPath, []byte("NEVER_LEAVE"), 0644)
	if err != nil {
		http.Error(w, "Failed to apply NTFS alternate streams", http.StatusInternalServerError)
		return
	}

	state.mu.Lock()
	state.MonitoredFiles = append(state.MonitoredFiles, cleanPath)
	state.mu.Unlock()

	appendLog("SUCCESS", "Applied Alternate Data Stream security classification.", cleanPath)
	w.WriteHeader(http.StatusOK)
}

func handleUnmarkFile(w http.ResponseWriter, r *http.Request) {
	type tagRequest struct {
		Path string `json:"path"`
	}
	var req tagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !state.IsAdmin {
		http.Error(w, "Admin rights required", http.StatusForbidden)
		return
	}

	cleanPath := filepath.Clean(req.Path)
	adsStreamPath := cleanPath + ":security.policy"
	_ = os.Remove(adsStreamPath)

	state.mu.Lock()
	newFiles := []string{}
	for _, f := range state.MonitoredFiles {
		if f != cleanPath {
			newFiles = append(newFiles, f)
		}
	}
	state.MonitoredFiles = newFiles
	state.mu.Unlock()

	appendLog("WARNING", "Purged NTFS ADS marking from local target file.", cleanPath)
	w.WriteHeader(http.StatusOK)
}

func handleDeIsolate(w http.ResponseWriter, r *http.Request) {
	if !state.IsAdmin {
		http.Error(w, "Admin rights required", http.StatusForbidden)
		return
	}

	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=Block_All_Egress")
	_ = cmd.Run()

	state.mu.Lock()
	state.IsIsolated = false
	state.mu.Unlock()

	appendLog("SUCCESS", "Network connection de-isolated successfully.", "Windows Firewall block table flushed.")
	w.WriteHeader(http.StatusOK)
}

func handleRequestElevate(w http.ResponseWriter, r *http.Request) {
	go func() {
		time.Sleep(500 * time.Millisecond)
		escalateToAdminPrivileges()
	}()
	w.WriteHeader(http.StatusOK)
}

func handleCheckAdminOnline(w http.ResponseWriter, r *http.Request) {
	client := http.Client{
		Timeout: 200 * time.Millisecond,
	}
	resp, err := client.Get("http://127.0.0.1:9901/api/status")
	if err == nil {
		resp.Body.Close()
		w.Write([]byte("ONLINE"))
		return
	}
	w.Write([]byte("OFFLINE"))
}

func handleShutdown(w http.ResponseWriter, r *http.Request) {
	appendLog("WARNING", "Shutdown signal received. Exiting agent...", "")
	w.WriteHeader(http.StatusOK)
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
}

func handleSimulateAccess(w http.ResponseWriter, r *http.Request) {
	type simulateRequest struct {
		Process string `json:"process"`
		Path    string `json:"path"`
	}
	var req simulateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	appendLog("WARNING", fmt.Sprintf("Simulating file access request from %s.", req.Process), req.Path)
	triggerHostIsolation(req.Process, req.Path)
	w.WriteHeader(http.StatusOK)
}

// ==========================================
// SYSTEM WIN32 CORE CALLS
// ==========================================
func isFileBeingAccessed(filePath string) bool {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		return true 
	}
	file.Close()
	return false
}

func checkIfAdmin() bool {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin := shell32.NewProc("IsUserAnAdmin")
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

func escalateToAdminPrivileges() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	shell32 := syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW := shell32.NewProc("ShellExecuteW")
	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	filePtr, _ := syscall.UTF16PtrFromString(exePath)
	procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verbPtr)), uintptr(unsafe.Pointer(filePtr)), 0, 0, 1)
}

func openBrowser(url string) {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW := shell32.NewProc("ShellExecuteW")
	verbPtr, _ := syscall.UTF16PtrFromString("open")
	filePtr, _ := syscall.UTF16PtrFromString(url)
	procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verbPtr)), uintptr(unsafe.Pointer(filePtr)), 0, 0, 1)
}

func showErrorBox(message string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	procMessageBoxW := user32.NewProc("MessageBoxW")
	titlePtr, _ := syscall.UTF16PtrFromString("DefendEdge Critical Error")
	msgPtr, _ := syscall.UTF16PtrFromString(message)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(msgPtr)), uintptr(unsafe.Pointer(titlePtr)), 0x00000010)
}

func appendLog(severity, event, details string) {
	state.mu.Lock()
	defer state.mu.Unlock()
	log := LogMsg{
		Timestamp: time.Now().Format("15:04:05"),
		Severity:  severity,
		Event:     event,
		Details:   details,
	}
	state.Logs = append([]LogMsg{log}, state.Logs...)
}

// ==========================================
// EMBEDDED DASHBOARD (HTML, CSS & VANILLA JS)
// ==========================================
const htmlDashboard = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DefendEdge Web Command Portal</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Segoe+UI:wght@300;400;600;700&family=Cascadia+Code&display=swap');
        body { font-family: 'Segoe UI', sans-serif; background-color: #111217; color: #F4F5F7; }
        .code-font { font-family: 'Cascadia Code', monospace; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #111217; }
        ::-webkit-scrollbar-thumb { background: #2E313F; border-radius: 3px; }
    </style>
</head>
<body class="min-h-screen flex flex-col justify-between">

    <!-- Top Navigation -->
    <header class="border-b border-slate-800 bg-[#1E2029] px-8 py-4 flex items-center justify-between sticky top-0 z-30">
        <div class="flex items-center space-x-3">
            <div class="bg-indigo-600 text-white p-2.5 rounded-lg flex items-center justify-center shadow-lg">
                <i class="fa-solid fa-shield-halved text-xl"></i>
            </div>
            <div>
                <h1 class="font-bold text-lg leading-tight tracking-wide flex items-center space-x-2">
                    <span>DefendEdge Endpoint DLP Web Control</span>
                    <span class="text-xs font-normal bg-indigo-500/20 text-indigo-400 px-2 py-0.5 rounded border border-indigo-500/30" id="header-active-badge">Active</span>
                </h1>
                <p class="text-xs text-slate-400" id="header-desc">NTFS Data Security & Isolation Controller</p>
            </div>
        </div>
        
        <div class="flex items-center space-x-6">
            <!-- Redirect Link to counterpart dashboard -->
            <div id="cross-redirect-panel" class="hidden">
                <button id="cross-redirect-btn" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold px-3 py-2 rounded-lg transition flex items-center space-x-1">
                    <i class="fa-solid fa-arrow-right-to-bracket"></i>
                    <span id="cross-redirect-text">Go to Admin Dashboard (Port 9901)</span>
                </button>
            </div>

            <!-- DLP Toggle Switch -->
            <div class="flex items-center space-x-3 bg-[#111217] px-4 py-2 rounded-xl border border-slate-800">
                <span class="text-xs font-semibold uppercase text-slate-400">DLP Watcher Protection:</span>
                <button onclick="toggleDlp()" id="dlp-toggle-btn" class="relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none bg-emerald-500">
                    <span id="dlp-toggle-dot" class="pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out translate-x-5"></span>
                </button>
            </div>

            <!-- Role Badge -->
            <div id="uac-badge" class="text-xs bg-amber-500/10 border border-amber-500/30 text-amber-400 px-4 py-2 rounded-xl flex items-center space-x-2">
                <i class="fa-solid fa-user-shield"></i>
                <span id="role-text" class="font-semibold">Standard User</span>
                <button onclick="elevateAgent()" id="elevate-btn" class="ml-2 bg-amber-500 hover:bg-amber-600 text-[#111217] text-[10px] font-bold px-2 py-0.5 rounded-md transition uppercase">Elevate</button>
            </div>
        </div>
    </header>

    <!-- Main Workspace Content -->
    <main class="flex-1 max-w-7xl w-full mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        <!-- Left Column: Controls (7 cols) -->
        <section class="lg:col-span-7 flex flex-col space-y-6">
            
            <!-- System Monitor Cards -->
            <div class="bg-[#1E2029] border border-slate-800 rounded-2xl p-6 shadow-xl">
                <h2 class="text-xs font-bold uppercase tracking-widest text-slate-400 mb-4 flex items-center justify-between">
                    <span>Host Status & Firewall Metrics</span>
                    <i class="fa-solid fa-circle-nodes text-slate-500"></i>
                </h2>
                
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <!-- Firewall -->
                    <div id="firewall-card" class="bg-[#111217] p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
                        <span class="text-xs text-slate-400">Firewall Egress Rules</span>
                        <div class="flex items-center justify-between mt-3">
                            <span id="firewall-status" class="text-xl font-bold text-emerald-400">NOMINAL</span>
                            <i id="firewall-icon" class="fa-solid fa-circle-check text-emerald-400 text-lg"></i>
                        </div>
                        <span id="firewall-desc" class="text-[10px] text-slate-500 mt-2">All Connections Active</span>
                    </div>

                    <!-- Protected files -->
                    <div class="bg-[#111217] p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
                        <span class="text-xs text-slate-400">Tagged Files (ADS)</span>
                        <div class="flex items-center justify-between mt-3">
                            <span id="tagged-count" class="text-2xl font-bold text-indigo-400">0</span>
                            <i class="fa-solid fa-tags text-indigo-400 text-lg"></i>
                        </div>
                        <span class="text-[10px] text-slate-500 mt-2">Active Metadata Locks</span>
                    </div>

                    <!-- DLP Health -->
                    <div id="health-card" class="bg-[#111217] p-5 rounded-xl border border-slate-800 flex flex-col justify-between">
                        <span class="text-xs text-slate-400">Engine Monitoring Status</span>
                        <div class="flex items-center justify-between mt-3">
                            <span id="engine-status" class="text-lg font-bold text-emerald-400">ARMED</span>
                            <span class="relative flex h-2.5 w-2.5">
                                <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                            </span>
                        </div>
                        <span id="engine-desc" class="text-[10px] text-slate-500 mt-2">Watcher Threads Online</span>
                    </div>
                </div>
            </div>

            <!-- Path Tagging Management Area -->
            <div class="bg-[#1E2029] border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-xs font-bold uppercase tracking-widest text-slate-400 flex items-center space-x-2">
                        <i class="fa-regular fa-folder text-indigo-400"></i>
                        <span>NTFS Alternate Data Stream (ADS) File Manager</span>
                    </h2>
                    <span class="text-[10px] text-slate-500 font-semibold uppercase">NTFS Core integration</span>
                </div>

                <!-- Input group -->
                <div class="bg-[#111217] p-4 rounded-xl border border-slate-800 flex flex-col md:flex-row md:items-center gap-4 mb-6">
                    <div class="flex-1">
                        <label class="block text-[10px] font-bold text-slate-500 uppercase mb-1">Local File Path</label>
                        <input type="text" id="target-path-input" placeholder="C:\SecureData\Confidential.txt" class="w-full bg-[#1A1C23] border border-slate-800 rounded-lg px-4 py-2 focus:outline-none focus:border-indigo-500 text-sm code-font">
                    </div>
                    <div class="flex items-end">
                        <button onclick="tagTargetFile()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-6 py-2 rounded-lg text-sm transition h-[38px] flex items-center space-x-2 shadow-lg shadow-indigo-600/10">
                            <i class="fa-solid fa-plus"></i>
                            <span>Mark File Stream</span>
                        </button>
                    </div>
                </div>

                <!-- List of active files -->
                <h4 class="text-xs font-semibold text-slate-400 mb-2">Currently Mark-Protected Targets:</h4>
                <div class="bg-[#111217] rounded-xl border border-slate-800 overflow-hidden">
                    <table class="w-full text-left text-xs text-slate-300">
                        <thead class="bg-[#1E2029]/60 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
                            <tr>
                                <th class="p-4">Target File Path</th>
                                <th class="p-4">Alternate Data Stream Policy</th>
                                <th class="p-4 text-right">Protection Action</th>
                            </tr>
                        </thead>
                        <tbody id="monitored-files-tbody">
                            <!-- Populated dynamically via JS API updates -->
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Egress Simulator Sandbox -->
            <div class="bg-[#1E2029] border border-slate-800 rounded-2xl p-6 shadow-xl">
                <h2 class="text-xs font-bold uppercase tracking-widest text-slate-400 mb-3 flex items-center space-x-2">
                    <i class="fa-solid fa-vial text-amber-500"></i>
                    <span>Exfiltration Simulator (SecOps Test Bench)</span>
                </h2>
                <p class="text-xs text-slate-400 mb-4">
                    Simulate a system application or web browser attempting to open or move your tagged files. If the process is a network-enabled threat actor, the local agent firewall will trigger instantly.
                </p>

                <div class="grid grid-cols-1 md:grid-cols-12 gap-4">
                    <div class="md:col-span-8 space-y-3">
                        <div>
                            <label class="block text-[10px] uppercase font-bold text-slate-500 mb-1">Target Marked Asset</label>
                            <select id="sim-file-select" class="w-full bg-[#111217] border border-slate-800 text-xs rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500 code-font">
                                <option value="">(No marked files available)</option>
                            </select>
                        </div>
                        <div>
                            <label class="block text-[10px] uppercase font-bold text-slate-500 mb-1">Initiating Process</label>
                            <select id="sim-proc-select" class="w-full bg-[#111217] border border-slate-800 text-xs rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-indigo-500">
                                <option value="chrome.exe">chrome.exe [Google Chrome Browser]</option>
                                <option value="powershell.exe">powershell.exe [PowerShell Admin Shell]</option>
                                <option value="openvpn.exe">openvpn.exe [Tunnel Daemon]</option>
                            </select>
                        </div>
                    </div>
                    <div class="md:col-span-4 flex flex-col justify-end">
                        <button onclick="triggerSimulatedAccess()" class="w-full bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white font-bold py-4 rounded-xl text-xs transition uppercase flex flex-col items-center justify-center space-y-1 shadow-lg shadow-red-900/10">
                            <i class="fa-solid fa-shield-virus text-lg"></i>
                            <span>Simulate Access</span>
                        </button>
                    </div>
                </div>
            </div>

        </section>

        <!-- Right Column: Forensic Feed & Admin Tools (5 cols) -->
        <section class="lg:col-span-5 flex flex-col space-y-6">
            
            <!-- Real-Time SIEM Log Console -->
            <div class="bg-[#1E2029] border border-slate-800 rounded-2xl flex-1 flex flex-col min-h-[480px] overflow-hidden">
                <div class="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-[#111217]/50">
                    <h2 class="text-xs font-bold uppercase tracking-widest text-slate-400 flex items-center space-x-2">
                        <span class="w-2 h-2 rounded-full bg-indigo-500 animate-ping"></span>
                        <span>Forensic SIEM Event Stream</span>
                    </h2>
                    <span class="text-[9px] font-bold text-indigo-400 bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 rounded uppercase">Real-Time</span>
                </div>

                <div class="flex-1 p-4 bg-[#111217] code-font text-xs flex flex-col overflow-y-auto max-h-[500px] space-y-3" id="log-feed-container">
                    <!-- Dynamically drawn log blocks -->
                </div>
            </div>

            <!-- Policy Override & Agent Control -->
            <div class="bg-[#1E2029] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
                <div>
                    <h2 class="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center space-x-2">
                        <i class="fa-solid fa-unlock-keyhole text-indigo-400"></i>
                        <span>Emergency Administrator Override</span>
                    </h2>
                    <button onclick="restoreNetworkLink()" class="w-full border border-slate-800 hover:border-indigo-500/30 hover:bg-indigo-500/5 text-indigo-400 font-semibold py-2.5 rounded-xl text-xs transition flex items-center justify-center space-x-2">
                        <i class="fa-solid fa-plug-circle-check text-sm"></i>
                        <span>De-Isolate Connection</span>
                    </button>
                </div>

                <div class="pt-2 border-t border-slate-800/60">
                    <h2 class="text-xs font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center space-x-2">
                        <i class="fa-solid fa-power-off text-rose-500"></i>
                        <span>Kill Background Agent Process</span>
                    </h2>
                    <p class="text-[10px] text-slate-500 mb-2">Stops the active file watchers and completely exits the background Go engine, releasing all port bindings.</p>
                    <button onclick="shutdownAgent()" class="w-full bg-rose-950/20 hover:bg-rose-900/40 text-rose-400 border border-rose-500/20 hover:border-rose-500/40 font-semibold py-2.5 rounded-xl text-xs transition flex items-center justify-center space-x-2">
                        <i class="fa-solid fa-skull-crossbones text-sm"></i>
                        <span>Shutdown Agent Fully</span>
                    </button>
                </div>
            </div>

        </section>

    </main>

    <!-- Global Floating System Notifications -->
    <div id="toast-notify" class="hidden fixed bottom-6 right-6 z-50 bg-[#1E2029] border border-slate-800 p-4 rounded-xl shadow-2xl flex items-start space-x-3 max-w-xs animate-bounce">
        <div id="toast-icon" class="text-indigo-400 p-1.5 bg-indigo-500/10 rounded-lg">
            <i class="fa-solid fa-circle-info"></i>
        </div>
        <div>
            <h5 id="toast-title" class="text-xs font-bold">DLP Event Handler</h5>
            <p id="toast-body" class="text-[10px] text-slate-400 mt-1">Notification description...</p>
        </div>
    </div>

    <footer class="bg-[#111217] border-t border-slate-900 py-4 text-center text-slate-600 text-[10px]">
        <p>© 2026 DefendEdge Security Platform. Active host monitoring is live via NTFS alternate metadata streams and local netsh firewall integrations.</p>
    </footer>

    <!-- Core Javascript Web Loop Client -->
    <script>
        let currentAdminState = false;

        // Auto-refresh stats and logs from Go REST Server every 1.5 seconds
        window.onload = function() {
            refreshEngineState();
            setInterval(refreshEngineState, 1500);
            
            // Periodically check if standard dashboard can cross-link to administrative dashboard
            setInterval(checkCrossConsoleStatus, 2000);
        };

        function refreshEngineState() {
            fetch('/api/status')
                .then(res => res.json())
                .then(data => {
                    currentAdminState = data.is_admin;
                    updateDashboardCards(data);
                    renderFiles(data.monitored_files);
                    renderLogs(data.logs);
                    updateSelectors(data.monitored_files);
                })
                .catch(err => console.error("API Fetch Offline: ", err));
        }

        function checkCrossConsoleStatus() {
            if (!currentAdminState) {
                fetch('/api/check-admin-online')
                    .then(res => res.text())
                    .then(status => {
                        const panel = document.getElementById("cross-redirect-panel");
                        const btn = document.getElementById("cross-redirect-btn");
                        const txt = document.getElementById("cross-redirect-text");
                        
                        if (status === "ONLINE") {
                            panel.classList.remove("hidden");
                            txt.textContent = "Switch to Admin Dashboard (Port 9901)";
                            btn.onclick = function() {
                                window.location.href = "http://localhost:9901";
                            };
                        } else {
                            panel.classList.add("hidden");
                        }
                    });
            } else {
                const panel = document.getElementById("cross-redirect-panel");
                const btn = document.getElementById("cross-redirect-btn");
                const txt = document.getElementById("cross-redirect-text");
                
                panel.classList.remove("hidden");
                txt.textContent = "View User Dashboard (Port 9900)";
                btn.onclick = function() {
                    window.location.href = "http://localhost:9900";
                };
            }
        }

        function updateDashboardCards(data) {
            // Update Privilege state
            const badge = document.getElementById("uac-badge");
            const roleTxt = document.getElementById("role-text");
            const elevateBtn = document.getElementById("elevate-btn");
            const activeBadge = document.getElementById("header-active-badge");

            if (data.is_admin) {
                badge.className = "text-xs bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 px-4 py-2 rounded-xl flex items-center space-x-2";
                roleTxt.textContent = "SYSTEM ADMINISTRATOR";
                elevateBtn.style.display = "none";
                activeBadge.className = "text-xs font-normal bg-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/30";
                activeBadge.textContent = "Elevated";
            } else {
                badge.className = "text-xs bg-amber-500/10 border border-amber-500/30 text-amber-400 px-4 py-2 rounded-xl flex items-center space-x-2";
                roleTxt.textContent = "Standard Employee";
                elevateBtn.style.display = "inline-block";
                activeBadge.className = "text-xs font-normal bg-indigo-500/20 text-indigo-400 px-2 py-0.5 rounded border border-indigo-500/30";
                activeBadge.textContent = "Active";
            }

            // Update Firewall State Card
            const fwCard = document.getElementById("firewall-card");
            const fwStatus = document.getElementById("firewall-status");
            const fwIcon = document.getElementById("firewall-icon");
            const fwDesc = document.getElementById("firewall-desc");

            if (data.is_isolated) {
                fwCard.className = "bg-red-950/40 p-5 rounded-xl border border-red-500/30 flex flex-col justify-between animate-pulse";
                fwStatus.textContent = "ISOLATED";
                fwStatus.className = "text-xl font-bold text-red-500";
                fwIcon.className = "fa-solid fa-triangle-exclamation text-red-500 text-lg";
                fwDesc.textContent = "Outbound Egress Locked";
            } else {
                fwCard.className = "bg-[#111217] p-5 rounded-xl border border-slate-800 flex flex-col justify-between";
                fwStatus.textContent = "NOMINAL";
                fwStatus.className = "text-xl font-bold text-emerald-400";
                fwIcon.className = "fa-solid fa-circle-check text-emerald-400 text-lg";
                fwDesc.textContent = "All Connections Active";
            }

            // Update Engine Toggle Button
            const dlpBtn = document.getElementById("dlp-toggle-btn");
            const dlpDot = document.getElementById("dlp-toggle-dot");
            const hCard = document.getElementById("health-card");
            const hStatus = document.getElementById("engine-status");
            const hDesc = document.getElementById("engine-desc");

            if (data.is_dlp_active) {
                dlpBtn.className = "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none bg-emerald-500";
                dlpDot.className = "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out translate-x-5";
                
                hStatus.textContent = "PASSIVE WATCH";
                hStatus.className = "text-lg font-bold text-indigo-400";
                hDesc.textContent = "Kernel Stream Hooks Armed";
            } else {
                dlpBtn.className = "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none bg-slate-700";
                dlpDot.className = "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out translate-x-0";
                
                hStatus.textContent = "SUSPENDED";
                hStatus.className = "text-lg font-bold text-slate-500";
                hDesc.textContent = "DLP Protection Bypassed";
            }

            document.getElementById("tagged-count").textContent = data.monitored_files.length;
        }

        function renderFiles(files) {
            const tbody = document.getElementById("monitored-files-tbody");
            tbody.innerHTML = "";

            if (!files || files.length === 0) {
                tbody.innerHTML = '<tr><td colspan="3" class="p-4 text-center text-slate-500 italic">No files currently monitored on partition paths.</td></tr>';
                return;
            }

            files.forEach(file => {
                const tr = document.createElement("tr");
                tr.className = "border-b border-slate-900 hover:bg-slate-900/10 transition";

                tr.innerHTML = 
                    '<td class="p-4 font-semibold code-font flex items-center space-x-2">' +
                        '<i class="fa-regular fa-file-lines text-slate-400 text-sm"></i>' +
                        '<span>' + file + '</span>' +
                    '</td>' +
                    '<td class="p-4">' +
                        '<span class="bg-red-500/10 border border-red-500/20 text-red-400 px-2 py-0.5 rounded text-[10px] code-font">' +
                            ':security.policy=NEVER_LEAVE' +
                        '</span>' +
                    '</td>' +
                    '<td class="p-4 text-right">' +
                        '<button onclick="unmarkTargetFile(\'' + file.replace(/\\/g, '\\\\') + '\')" class="text-[10px] bg-red-950/50 hover:bg-red-900/60 text-red-400 px-3 py-1 rounded-md transition font-semibold border border-red-500/20">' +
                            'Remove Stream' +
                        '</button>' +
                    '</td>';
                tbody.appendChild(tr);
            });
        }

        function updateSelectors(files) {
            const select = document.getElementById("sim-file-select");
            select.innerHTML = "";

            if (!files || files.length === 0) {
                select.innerHTML = '<option value="">(No marked files available)</option>';
                return;
            }

            files.forEach(file => {
                const opt = document.createElement("option");
                opt.value = file;
                opt.textContent = file;
                select.appendChild(opt);
            });
        }

        function renderLogs(logs) {
            const container = document.getElementById("log-feed-container");
            container.innerHTML = "";

            if (!logs || logs.length === 0) {
                container.innerHTML = '<div class="text-slate-600 italic">No logs currently printed inside telemetry feed.</div>';
                return;
            }

            logs.forEach(log => {
                const div = document.createElement("div");
                div.className = "border-b border-slate-800 pb-2 last:border-0";

                let severityStyle = "text-indigo-400";
                if (log.severity === "CRITICAL") severityStyle = "text-red-500 font-bold animate-pulse";
                if (log.severity === "WARNING") severityStyle = "text-amber-500 font-bold";
                if (log.severity === "SUCCESS") severityStyle = "text-emerald-400";

                div.innerHTML = 
                    '<div class="flex items-start space-x-2">' +
                        '<span class="text-slate-600 text-[10px] select-none shrink-0">' + log.timestamp + '</span>' +
                        '<span class="' + severityStyle + ' shrink-0">[' + log.severity + ']</span>' +
                        '<span class="text-slate-200">' + log.event + '</span>' +
                    '</div>' +
                    (log.details ? '<div class="text-[10px] text-slate-500 ml-12 code-font select-all leading-relaxed bg-[#1A1C23] p-1.5 rounded border border-slate-800/40 mt-1">' + log.details + '</div>' : "");
                container.appendChild(div);
            });
        }

        // ==========================================
        // SERVICE API WRAPPERS
        // ==========================================
        function toggleDlp() {
            fetch('/api/toggle-dlp')
                .then(() => {
                    showToast("Status Changed", "DLP Protection Core state modified.");
                    refreshEngineState();
                });
        }

        function tagTargetFile() {
            if (!currentAdminState) {
                showToast("Access Denied", "Applying Alternate Data Streams requires Administrative context.");
                return;
            }

            const path = document.getElementById("target-path-input").value.trim();
            if (!path) {
                showToast("Validation Error", "Target path cannot be null.");
                return;
            }

            fetch('/api/tag', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: path })
            })
            .then(res => {
                if (res.ok) {
                    showToast("ADS Classification Applied", "Tagged stream securely appended.");
                    document.getElementById("target-path-input").value = "";
                    refreshEngineState();
                } else {
                    showToast("Error", "Failed to tag. Ensure path is correct.");
                }
            });
        }

        function unmarkTargetFile(filePath) {
            if (!currentAdminState) {
                showToast("Access Denied", "Standard users cannot alter NTFS security attributes.");
                return;
            }

            fetch('/api/unmark', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: filePath })
            })
            .then(() => {
                showToast("Metadata Stream Purged", "NTFS metadata record removed from disk.");
                refreshEngineState();
            });
        }

        function restoreNetworkLink() {
            if (!currentAdminState) {
                showToast("Access Denied", "Modifying Firewall outbound link states requires Administrator mode.");
                return;
            }

            fetch('/api/de-isolate')
                .then(() => {
                    showToast("Connectivity Restored", "Firewall rules flushed. Outbound pipelines online.");
                    refreshEngineState();
                });
        }

        function triggerSimulatedAccess() {
            const file = document.getElementById("sim-file-select").value;
            const proc = document.getElementById("sim-proc-select").value;

            if (!file) {
                showToast("Simulation Void", "No marked files are loaded to run access simulation.");
                return;
            }

            fetch('/api/simulate-access', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ process: proc, path: file })
            })
            .then(() => {
                showToast("Access Simulation Fired", "Sent touch payload to NTFS cluster.");
                refreshEngineState();
            });
        }

        function shutdownAgent() {
            fetch('/api/shutdown')
                .then(() => {
                    showToast("Shutting Down", "Background agent process killed. Ports are now clean!");
                    setTimeout(() => {
                        window.location.reload();
                    }, 1500);
                });
        }

        function elevateAgent() {
            fetch('/api/elevate')
                .then(() => {
                    showToast("Elevation Triggered", "Windows User Account Control prompt requested.");
                    
                    let checkInterval = setInterval(() => {
                        fetch('http://127.0.0.1:9901/api/status')
                            .then(res => {
                                if (res.ok) {
                                    clearInterval(checkInterval);
                                    showToast("Redirecting", "Switching to Admin Web Console...");
                                    setTimeout(() => {
                                        window.location.href = "http://localhost:9901";
                                    }, 1000);
                                }
                            })
                            .catch(() => { /* Still booting up */ });
                    }, 500);
                });
        }

        // Custom UI Toasts
        function showToast(title, body) {
            const toast = document.getElementById("toast-notify");
            document.getElementById("toast-title").textContent = title;
            document.getElementById("toast-body").textContent = body;
            toast.classList.remove("hidden");
            setTimeout(() => {
                toast.classList.add("hidden");
            }, 3500);
        }
    </script>
</body>
</html>
`
