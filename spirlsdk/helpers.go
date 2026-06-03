package spirlsdk

// Optional returns a pointer to the given value. Uses &t instead of new(t)
// because the SDK targets Go 1.25 (new(value) requires Go 1.26).
// TODO: Can be switched to return new(t) once the SDK requires Go 1.26.
func Optional[T any](t T) *T {
	v := t
	return &v
}
