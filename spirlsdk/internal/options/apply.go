package options

func Apply[C any, O func(*C)](c *C, overrides []O, defaults ...O) {
	for _, opt := range defaults {
		opt(c)
	}
	for _, opt := range overrides {
		opt(c)
	}
}
