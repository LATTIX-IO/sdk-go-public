//go:build rustbindings && cgo && !windows

package sdk

/*
#cgo linux LDFLAGS: -lsdk_rust -ldl -lm -lpthread
#cgo darwin LDFLAGS: -lsdk_rust
#include <stdlib.h>
#include <lattix_sdk.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"unsafe"
)

type ffiBinding struct {
	handle *C.ClientHandle
}

func newBinding(options Options) (binding, error) {
	encoded, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}
	encodedCString := C.CString(string(encoded))
	defer C.free(unsafe.Pointer(encodedCString))

	handle := C.lattix_sdk_client_new(encodedCString)
	if handle == nil {
		return nil, lastRustError()
	}

	return &ffiBinding{handle: handle}, nil
}

func (b *ffiBinding) Call(method string, payload []byte) ([]byte, error) {
	if b.handle == nil {
		return nil, errors.New("Rust SDK handle is not initialized")
	}

	switch method {
	case "capabilities":
		return b.callNoPayload(sdkCapabilities)
	case "whoami":
		return b.callNoPayload(sdkWhoAmI)
	case "bootstrap":
		return b.callNoPayload(sdkBootstrap)
	case "exchange_session":
		return b.callNoPayload(sdkExchangeSession)
	case "protection_plan":
		return b.callWithPayload(sdkProtectionPlan, payload)
	case "policy_resolve":
		return b.callWithPayload(sdkPolicyResolve, payload)
	case "key_access_plan":
		return b.callWithPayload(sdkKeyAccessPlan, payload)
	case "artifact_register":
		return b.callWithPayload(sdkArtifactRegister, payload)
	case "evidence":
		return b.callWithPayload(sdkEvidence, payload)
	default:
		return nil, errors.New("unsupported Rust SDK operation: " + method)
	}
}

func (b *ffiBinding) Close() error {
	if b.handle != nil {
		C.lattix_sdk_client_free(b.handle)
		b.handle = nil
	}
	return nil
}

type noPayloadFunc func(*C.ClientHandle) *C.char

type payloadFunc func(*C.ClientHandle, *C.char) *C.char

func sdkCapabilities(handle *C.ClientHandle) *C.char {
	return C.lattix_sdk_capabilities(handle)
}

func sdkWhoAmI(handle *C.ClientHandle) *C.char {
	return C.lattix_sdk_whoami(handle)
}

func sdkBootstrap(handle *C.ClientHandle) *C.char {
	return C.lattix_sdk_bootstrap(handle)
}

func sdkExchangeSession(handle *C.ClientHandle) *C.char {
	return C.lattix_sdk_exchange_session(handle)
}

func sdkProtectionPlan(handle *C.ClientHandle, payload *C.char) *C.char {
	return C.lattix_sdk_protection_plan(handle, payload)
}

func sdkPolicyResolve(handle *C.ClientHandle, payload *C.char) *C.char {
	return C.lattix_sdk_policy_resolve(handle, payload)
}

func sdkKeyAccessPlan(handle *C.ClientHandle, payload *C.char) *C.char {
	return C.lattix_sdk_key_access_plan(handle, payload)
}

func sdkArtifactRegister(handle *C.ClientHandle, payload *C.char) *C.char {
	return C.lattix_sdk_artifact_register(handle, payload)
}

func sdkEvidence(handle *C.ClientHandle, payload *C.char) *C.char {
	return C.lattix_sdk_evidence(handle, payload)
}

func (b *ffiBinding) callNoPayload(fn noPayloadFunc) ([]byte, error) {
	result := fn(b.handle)
	return rustString(result)
}

func (b *ffiBinding) callWithPayload(fn payloadFunc, payload []byte) ([]byte, error) {
	payloadCString := C.CString(string(payload))
	defer C.free(unsafe.Pointer(payloadCString))

	result := fn(b.handle, payloadCString)
	return rustString(result)
}

func rustString(value *C.char) ([]byte, error) {
	if value == nil {
		return nil, lastRustError()
	}
	defer C.lattix_sdk_string_free(value)

	return []byte(C.GoString(value)), nil
}

func lastRustError() error {
	message := C.lattix_sdk_last_error_message()
	if message == nil {
		return errors.New("Rust SDK returned an unknown error")
	}
	defer C.lattix_sdk_string_free(message)

	goMessage := C.GoString(message)
	if goMessage == "" {
		return errors.New("Rust SDK returned an unknown error")
	}
	return errors.New(goMessage)
}
