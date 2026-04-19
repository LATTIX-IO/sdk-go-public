//go:build rustbindings && windows

package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

type windowsBinding struct {
	handle uintptr
	lib    *windowsRustLibrary
}

type windowsRustLibrary struct {
	dll                  *syscall.LazyDLL
	lastErrorMessageProc *syscall.LazyProc
	stringFreeProc       *syscall.LazyProc
	clientNewProc        *syscall.LazyProc
	clientFreeProc       *syscall.LazyProc
	capabilitiesProc     *syscall.LazyProc
	whoAmIProc           *syscall.LazyProc
	bootstrapProc        *syscall.LazyProc
	exchangeSessionProc  *syscall.LazyProc
	protectionPlanProc   *syscall.LazyProc
	policyResolveProc    *syscall.LazyProc
	keyAccessPlanProc    *syscall.LazyProc
	artifactRegisterProc *syscall.LazyProc
	evidenceProc         *syscall.LazyProc
}

var (
	windowsRustLibraryOnce sync.Once
	windowsRustLibraryRef  *windowsRustLibrary
	windowsRustLibraryErr  error
)

func newBinding(options Options) (binding, error) {
	lib, err := loadWindowsRustLibrary()
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	result, _, _ := lib.clientNewProc.Call(uintptr(unsafe.Pointer(syscallBytePtr(encoded))))
	if result == 0 {
		return nil, lib.lastRustError()
	}

	return &windowsBinding{handle: result, lib: lib}, nil
}

func (b *windowsBinding) Call(method string, payload []byte) ([]byte, error) {
	if b.handle == 0 {
		return nil, errors.New("Rust SDK handle is not initialized")
	}

	switch method {
	case "capabilities":
		return b.callNoPayload(b.lib.capabilitiesProc)
	case "whoami":
		return b.callNoPayload(b.lib.whoAmIProc)
	case "bootstrap":
		return b.callNoPayload(b.lib.bootstrapProc)
	case "exchange_session":
		return b.callNoPayload(b.lib.exchangeSessionProc)
	case "protection_plan":
		return b.callWithPayload(b.lib.protectionPlanProc, payload)
	case "policy_resolve":
		return b.callWithPayload(b.lib.policyResolveProc, payload)
	case "key_access_plan":
		return b.callWithPayload(b.lib.keyAccessPlanProc, payload)
	case "artifact_register":
		return b.callWithPayload(b.lib.artifactRegisterProc, payload)
	case "evidence":
		return b.callWithPayload(b.lib.evidenceProc, payload)
	default:
		return nil, errors.New("unsupported Rust SDK operation: " + method)
	}
}

func (b *windowsBinding) Close() error {
	if b.handle != 0 {
		b.lib.clientFreeProc.Call(b.handle)
		b.handle = 0
	}
	return nil
}

func (b *windowsBinding) callNoPayload(proc *syscall.LazyProc) ([]byte, error) {
	result, _, _ := proc.Call(b.handle)
	return b.lib.consumeRustString(result)
}

func (b *windowsBinding) callWithPayload(proc *syscall.LazyProc, payload []byte) ([]byte, error) {
	result, _, _ := proc.Call(b.handle, uintptr(unsafe.Pointer(syscallBytePtr(payload))))
	return b.lib.consumeRustString(result)
}

func loadWindowsRustLibrary() (*windowsRustLibrary, error) {
	windowsRustLibraryOnce.Do(func() {
		libraryPath, err := resolveWindowsRustLibraryPath()
		if err != nil {
			windowsRustLibraryErr = err
			return
		}

		dll := syscall.NewLazyDLL(libraryPath)
		lib := &windowsRustLibrary{
			dll:                  dll,
			lastErrorMessageProc: dll.NewProc("lattix_sdk_last_error_message"),
			stringFreeProc:       dll.NewProc("lattix_sdk_string_free"),
			clientNewProc:        dll.NewProc("lattix_sdk_client_new"),
			clientFreeProc:       dll.NewProc("lattix_sdk_client_free"),
			capabilitiesProc:     dll.NewProc("lattix_sdk_capabilities"),
			whoAmIProc:           dll.NewProc("lattix_sdk_whoami"),
			bootstrapProc:        dll.NewProc("lattix_sdk_bootstrap"),
			exchangeSessionProc:  dll.NewProc("lattix_sdk_exchange_session"),
			protectionPlanProc:   dll.NewProc("lattix_sdk_protection_plan"),
			policyResolveProc:    dll.NewProc("lattix_sdk_policy_resolve"),
			keyAccessPlanProc:    dll.NewProc("lattix_sdk_key_access_plan"),
			artifactRegisterProc: dll.NewProc("lattix_sdk_artifact_register"),
			evidenceProc:         dll.NewProc("lattix_sdk_evidence"),
		}

		if err := lib.dll.Load(); err != nil {
			windowsRustLibraryErr = fmt.Errorf("%w: %v", newWindowsBindingUnavailableError(), err)
			return
		}

		for _, proc := range []*syscall.LazyProc{
			lib.lastErrorMessageProc,
			lib.stringFreeProc,
			lib.clientNewProc,
			lib.clientFreeProc,
			lib.capabilitiesProc,
			lib.whoAmIProc,
			lib.bootstrapProc,
			lib.exchangeSessionProc,
			lib.protectionPlanProc,
			lib.policyResolveProc,
			lib.keyAccessPlanProc,
			lib.artifactRegisterProc,
			lib.evidenceProc,
		} {
			if err := proc.Find(); err != nil {
				windowsRustLibraryErr = fmt.Errorf("failed to find Rust SDK export %q: %w", proc.Name, err)
				return
			}
		}

		windowsRustLibraryRef = lib
	})

	if windowsRustLibraryErr != nil {
		return nil, windowsRustLibraryErr
	}
	return windowsRustLibraryRef, nil
}

func resolveWindowsRustLibraryPath() (string, error) {
	var candidates []string
	if envPath := os.Getenv("LATTIX_SDK_RUST_LIB"); envPath != "" {
		candidates = append(candidates, envPath)
	}

	if executablePath, err := os.Executable(); err == nil {
		executableDir := filepath.Dir(executablePath)
		candidates = append(candidates,
			filepath.Join(executableDir, "sdk_rust.dll"),
			filepath.Join(executableDir, "native", "sdk_rust.dll"),
		)
	}

	if workingDir, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(workingDir, "sdk_rust.dll"),
			filepath.Join(workingDir, "native", "sdk_rust.dll"),
		)
	}

	if _, currentFile, _, ok := runtime.Caller(0); ok {
		defaultPath := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "sdk-rust", "target", "release", "sdk_rust.dll"))
		candidates = append(candidates, defaultPath)
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	if len(candidates) == 0 {
		return "", newWindowsBindingUnavailableError()
	}

	return "", fmt.Errorf("%w. searched: %v", newWindowsBindingUnavailableError(), candidates)
}

func (lib *windowsRustLibrary) consumeRustString(ptr uintptr) ([]byte, error) {
	if ptr == 0 {
		return nil, lib.lastRustError()
	}
	defer lib.stringFreeProc.Call(ptr)

	return []byte(readCString(ptr)), nil
}

func (lib *windowsRustLibrary) lastRustError() error {
	ptr, _, _ := lib.lastErrorMessageProc.Call()
	if ptr == 0 {
		return errors.New("Rust SDK returned an unknown error")
	}
	defer lib.stringFreeProc.Call(ptr)

	message := readCString(ptr)
	if message == "" {
		return errors.New("Rust SDK returned an unknown error")
	}
	return errors.New(message)
}

func readCString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}

	buf := make([]byte, 0, 256)
	for offset := uintptr(0); ; offset++ {
		value := *(*byte)(unsafe.Pointer(ptr + offset))
		if value == 0 {
			break
		}
		buf = append(buf, value)
	}

	return string(buf)
}

func syscallBytePtr(payload []byte) *byte {
	buf := make([]byte, len(payload)+1)
	copy(buf, payload)
	return &buf[0]
}
