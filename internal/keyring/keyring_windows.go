//go:build windows

package keyring

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"
)

const isWindows = true

// CRYPTPROTECT_UI_FORBIDDEN keeps DPAPI from showing a prompt; it fails
// instead, which is the right behaviour for a service.
const cryptProtectUIForbidden = 0x1

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtect   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32.NewProc("CryptUnprotectData")
	procLocalFree      = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func protect(_ string, plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("cannot wrap an empty master key")
	}
	in := dataBlob{cbData: uint32(len(plain)), pbData: &plain[0]}
	var out dataBlob
	ret, _, errno := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // description
		0, // optional entropy
		0, // reserved
		0, // prompt struct
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(plain)
	if ret == 0 {
		return nil, errno
	}
	return copyAndFree(&out)
}

func unprotect(_ string, wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, errors.New("empty master key file")
	}
	in := dataBlob{cbData: uint32(len(wrapped)), pbData: &wrapped[0]}
	var out dataBlob
	ret, _, errno := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // description out
		0, // optional entropy
		0, // reserved
		0, // prompt struct
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(wrapped)
	if ret == 0 {
		return nil, errno
	}
	return copyAndFree(&out)
}

func copyAndFree(blob *dataBlob) ([]byte, error) {
	if blob.pbData == nil || blob.cbData == 0 {
		return nil, errors.New("dpapi returned an empty blob")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(blob.pbData)))
	src := unsafe.Slice(blob.pbData, blob.cbData)
	out := make([]byte, len(src))
	copy(out, src)
	return out, nil
}
