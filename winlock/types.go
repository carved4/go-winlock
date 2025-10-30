package main

import (

	wc "github.com/carved4/go-wincall"
)

var (
	bcryptBase                   uintptr = wc.LoadLibraryLdr("bcrypt.dll")
	bCryptSetProperty            uintptr = wc.GetFunctionAddress(bcryptBase, wc.GetHash("BCryptSetProperty"))
	bCryptOpenAlgorithmProvider  uintptr = wc.GetFunctionAddress(bcryptBase, wc.GetHash("BCryptOpenAlgorithmProvider"))
	bCryptGenerateSymmetricKey   uintptr = wc.GetFunctionAddress(bcryptBase, wc.GetHash("BCryptGenerateSymmetricKey"))
	bCryptDestroyKey             uintptr = wc.GetFunctionAddress(bcryptBase, wc.GetHash("BCryptDestroyKey"))
	bCryptGetProperty            uintptr = wc.GetFunctionAddress(bcryptBase, wc.GetHash("BCryptGetProperty"))
	bCryptDecryptAddr            uintptr = wc.GetFunctionAddress(bcryptBase, wc.GetHash("BCryptDecrypt"))
	bCryptEncrypt                uintptr = wc.GetFunctionAddress(bcryptBase, wc.GetHash("BCryptEncrypt"))
	bCryptCloseAlgorithmProvider uintptr = wc.GetFunctionAddress(bcryptBase, wc.GetHash("BCryptCloseAlgorithmProvider"))
	k32Base                      uintptr = wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	readFileAddr                 uintptr = wc.GetFunctionAddress(k32Base, wc.GetHash("ReadFile"))
	createFileAddr               uintptr = wc.GetFunctionAddress(k32Base, wc.GetHash("CreateFileW"))
	closeHandleAddr              uintptr = wc.GetFunctionAddress(k32Base, wc.GetHash("CloseHandle"))
	getFileSizeAddr              uintptr = wc.GetFunctionAddress(k32Base, wc.GetHash("GetFileSize"))
	getLastErrorAddr             uintptr = wc.GetFunctionAddress(k32Base, wc.GetHash("GetLastError"))
	bCryptGenRandom              uintptr = wc.GetFunctionAddress(bcryptBase, wc.GetHash("BCryptGenRandom"))
	writeFileAddr                uintptr = wc.GetFunctionAddress(k32Base, wc.GetHash("WriteFile"))
	findFirstFileAddr            uintptr = wc.GetFunctionAddress(k32Base, wc.GetHash("FindFirstFileW"))
	findNextFileAddr             uintptr = wc.GetFunctionAddress(k32Base, wc.GetHash("FindNextFileW"))
	findCloseAddr                uintptr = wc.GetFunctionAddress(k32Base, wc.GetHash("FindClose"))
)

const (
	BCRYPT_AES_ALGORITHM            = "AES"
	BCRYPT_CHAINING_MODE            = "ChainingMode"
	BCRYPT_CHAIN_MODE_CBC           = "ChainingModeCBC"
	BCRYPT_OBJECT_LENGTH            = "ObjectLength"
	BCRYPT_BLOCK_LENGTH             = "BlockLength"
	BCRYPT_BLOCK_PADDING            = 0x00000001
	BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
	FILE_ATTRIBUTE_DIRECTORY        = 0x10
	INVALID_HANDLE_VALUE            = ^uintptr(0)
)

type BCryptHandle uintptr

type WIN32_FIND_DATAW struct {
	DwFileAttributes   uint32
	FtCreationTime     [8]byte
	FtLastAccessTime   [8]byte
	FtLastWriteTime    [8]byte
	NFileSizeHigh      uint32
	NFileSizeLow       uint32
	DwReserved0        uint32
	DwReserved1        uint32
	CFileName          [260]uint16
	CAlternateFileName [14]uint16
}

type STARTUPINFO struct {
	cb              uint32
	lpReserved      *uint16
	lpDesktop       *uint16
	lpTitle         *uint16
	dwX             uint32
	dwY             uint32
	dwXSize         uint32
	dwYSize         uint32
	dwXCountChars   uint32
	dwYCountChars   uint32
	dwFillAttribute uint32
	dwFlags         uint32
	wShowWindow     uint16
	cbReserved2     uint16
	lpReserved2     *byte
	hStdInput       uintptr
	hStdOutput      uintptr
	hStdError       uintptr
}

type PROCESS_INFORMATION struct {
	hProcess    uintptr
	hThread     uintptr
	dwProcessId uint32
	dwThreadId  uint32
}

type SECURITY_ATTRIBUTES struct {
	nLength              uint32
	lpSecurityDescriptor uintptr
	bInheritHandle       uint32
}

type TOKEN_ELEVATION struct {
	TokenIsElevated uint32
}