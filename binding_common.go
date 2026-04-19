package sdk

import "fmt"

func newBindingUnavailableError() error {
	return fmt.Errorf("Rust bindings are not enabled; rebuild with -tags rustbindings after installing the matching sdk-rust native library and exposing its header/library search path")
}

func newWindowsBindingUnavailableError() error {
	return fmt.Errorf("Rust bindings are enabled, but the Windows DLL bridge could not load sdk_rust.dll. Install the matching native release, place the DLL next to your executable, or set LATTIX_SDK_RUST_LIB")
}
