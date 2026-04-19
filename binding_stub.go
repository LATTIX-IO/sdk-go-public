//go:build !rustbindings

package sdk

func newBinding(_ Options) (binding, error) {
	return nil, newBindingUnavailableError()
}
