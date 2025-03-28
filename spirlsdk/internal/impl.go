package internal

// Intf is embedded into interfaces to enforce that only SDK-provided
// implementations are used.
type Intf interface {
	internal()
}

// Impl is embedded into implementation structs to implement Impl.
type Impl struct{}

func (Impl) internal() {}
