package spirlsdk

func Optional[T any](t T) *T {
	return &t
}
