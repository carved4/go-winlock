# go-winlock

ransomware emulation tool for red team exercises and defensive training. implements file encryption using windows bcrypt api with pure winapi calls through go-wincall.

## warning

this tool is designed for authorized security testing only. running this on systems without explicit permission is illegal and unethical. the authors are not responsible for misuse. by using this tool, you accept full responsibility for your actions.

- encrypts files in place, destroying original content
- deletes volume shadow copies when run with admin privileges
- cannot recover files without the encryption key
- test only on isolated systems or vms

## technical implementation

### architecture

the project consists of two components:
- `winlock/` - encrypter binary
- `dec/` - decrypter binary

### winapi usage

all file operations, cryptography, and system interactions are implemented via direct winapi calls using go-wincall, avoiding golang's standard library where possible for operational security.

#### encryption (bcrypt.dll)
- `BCryptOpenAlgorithmProvider` - initializes aes algorithm handle
- `BCryptSetProperty` - configures cbc chaining mode
- `BCryptGetProperty` - queries key object size and block length
- `BCryptGenerateSymmetricKey` - creates aes-256 key handle from random bytes
- `BCryptGenRandom` - generates cryptographically secure iv (uses `BCRYPT_USE_SYSTEM_PREFERRED_RNG`)
- `BCryptEncrypt` / `BCryptDecrypt` - performs actual encryption/decryption with `BCRYPT_BLOCK_PADDING`

#### file operations (kernel32.dll)
- `CreateFileW` - opens files with `GENERIC_READ` or `GENERIC_WRITE`, uses `FILE_SHARE_READ|FILE_SHARE_WRITE` and `FILE_FLAG_SEQUENTIAL_SCAN`
- `ReadFile` / `WriteFile` - chunked i/o (64mb chunks) to handle files >2gb
- `GetFileSize` - retrieves 64-bit file size using high/low dword pattern
- `FindFirstFileW` / `FindNextFileW` - recursive directory traversal
- `CloseHandle` - resource cleanup

#### privilege operations (advapi32.dll)
- `GetCurrentProcess` / `OpenProcessToken` - acquires process token handle with `TOKEN_QUERY` access
- `GetTokenInformation` - checks `TokenElevation` (class 20) to detect admin privileges

#### process execution
- `CreateProcessW` - executes vssadmin with `CREATE_NO_WINDOW` flag to delete shadow copies silently
- `CreatePipe` - captures command output via redirected stdout/stderr

### encryption scheme

**algorithm**: aes-256-cbc with pkcs#7 padding

**key generation**: 32 bytes from `crypto/rand` (go stdlib - acceptable for poc)

**iv handling**: 
- random 16-byte iv generated per file via `BCryptGenRandom`
- stored as first 16 bytes of encrypted file
- preserved for cbc chaining across chunks

**file structure**:
```
[16 bytes IV][encrypted data with padding]
```

### large file handling

files are processed differently based on size:

**small files (≤256mb)**:
- single-pass encryption/decryption
- padding applied in one operation
- optimal for bcrypt's 32-bit size parameters

**large files (>256mb)**:
- chunked processing (256mb chunks aligned to block size)
- cbc iv automatically updated by bcrypt across chunks
- padding only applied to final chunk
- prevents `STATUS_INVALID_BUFFER_SIZE (0xc0000206)` errors

**read operations**:
- files >2gb handled via 64-bit size calculation (`fileSizeHigh<<32 | fileSizeLow`)
- chunked reads (64mb) to avoid windows readfile limitations
- 2gb memory limit enforced for safety

### admin privilege detection

uses token elevation query:
1. opens current process token with `TOKEN_QUERY` (0x0008)
2. calls `GetTokenInformation` with `TokenElevation` class (20)
3. checks `TOKEN_ELEVATION.TokenIsElevated` field
4. if elevated, executes vss deletion before encryption

### shadow copy deletion

when admin privileges detected:
```
cmd.exe /c vssadmin delete shadows /all /for=c: /quiet
```
- executed via `CreateProcessW` with `CREATE_NO_WINDOW` (0x08000000)
- stdout/stderr captured through anonymous pipe
- prevents recovery via volume shadow copy service

## usage

### building

```bash
# build encrypter
cd winlock
go build -o encrypter.exe

# build decrypter  
cd ../dec
go build -o decrypter.exe
```

### encryption

```bash
# encrypt directory (prints hex key to stdout)
.\encrypter.exe -path "C:\target\directory"

# example output:
# f40773ae66dde5d1631e193a967182829f217e708e35ae6191dddc104da66a9c
# found 4 files to encrypt
# encrypted: C:\target\directory\file1.pdf
# encrypted: C:\target\directory\file2.docx
```

**if run as administrator**: automatically deletes vss before encryption

### decryption

```bash
# decrypt with key from encryption output
.\decrypter.exe -path "C:\target\directory" -key f40773ae66dde5d1631e193a967182829f217e708e35ae6191dddc104da66a9c

# example output:
# found 4 files to decrypt
# decrypted: C:\target\directory\file1.pdf
# decrypted: C:\target\directory\file2.docx
# decryption complete!
```

### targeted file extensions

the following extensions are encrypted:
- documents: `.txt`, `.csv`, `.xlsx`, `.pdf`, `.docx`, `.rtf`
- databases: `.sqlite`, `.db`
- archives: `.zip`, `.tar`, `.tar.gz`
- media: `.mp4`
- crypto: `.pem`, `.key`, `.pub`
- binaries: `.bin`

modify the `targetExtensions` map in `encrypt.go` / `decrypt.go` to adjust scope.

## common issues

### status_invalid_buffer_size (0xc0000206)
indicates bcrypt buffer size exceeds 32-bit limit. this is handled automatically via chunked processing for files >256mb.

### readfile returns 0 bytes
typically caused by:
- incorrect file sharing flags (fixed: uses `FILE_SHARE_READ|FILE_SHARE_WRITE`)
- file size >4gb with 32-bit size retrieval (fixed: uses 64-bit size calculation)

### bcryptsetproperty failed (0xc0000008)
`STATUS_INVALID_HANDLE` from concurrent bcrypt operations. this implementation uses sequential processing to avoid race conditions.

## defensive considerations

**detection vectors**:
- bcrypt api calls (aes-256-cbc pattern)
- recursive file enumeration via findnextfilew
- vssadmin execution with shadow deletion flags
- token elevation queries
- mass file modification events

**prevention**:
- restrict bcrypt.dll access for unprivileged processes
- monitor vssadmin.exe executions
- implement file system audit policies
- restrict token query privileges
- use application whitelisting

## dependencies

- [go-wincall](https://github.com/carved4/go-wincall) - pure winapi bindings for go

## license

use at your own risk. see warning section.

>really please do not run this on ur machine