//go:build rustbindings && !cgo && !windows

package sdk

func newBinding(_ Options) (binding, error) {
	return nil, newBindingUnavailableError()
}
