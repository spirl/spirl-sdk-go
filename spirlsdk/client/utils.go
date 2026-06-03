package client

import (
	"crypto/x509"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Optional returns a pointer to the given value. Uses &t instead of new(t)
// because the SDK targets Go 1.25 (new(value) requires Go 1.26).
// TODO: Can be switched to return new(t) once the SDK requires Go 1.26.
func ptrOf[T any](t T) *T {
	v := t
	return &v
}

func optionalValue[T any](pt *T) (t T) {
	if pt != nil {
		t = *pt
	}
	return t
}

func optionalValue1[T, U any](pt *T, f1 func(T) U) (u U) {
	if pt != nil {
		u = f1(*pt)
	}
	return u
}

func optionalValue2[T, U, V any](pt *T, f1 func(T) U, f2 func(U) V) (v V) {
	if pt != nil {
		v = f2(f1(*pt))
	}
	return v
}

func timeFromAPI(ts *timestamppb.Timestamp) time.Time {
	if ts.IsValid() {
		return ts.AsTime()
	}
	return time.Time{}
}

func durationToAPI(d time.Duration) *durationpb.Duration {
	return durationpb.New(d)
}

func durationFromAPI(ts *durationpb.Duration) time.Duration {
	if ts.IsValid() {
		return ts.AsDuration()
	}
	return 0
}

func mapSlice[Out, In any](ins []In, mapper func(In) Out) []Out {
	if ins == nil {
		return nil
	}
	outs := make([]Out, 0, len(ins))
	for _, in := range ins {
		outs = append(outs, mapper(in))
	}
	return outs
}

func convertSlice[Out, In any](ins []In, converter func(In) (Out, error)) ([]Out, error) {
	if ins == nil {
		return nil, nil
	}
	outs := make([]Out, 0, len(ins))
	for _, in := range ins {
		out, err := converter(in)
		if err != nil {
			return nil, err
		}
		outs = append(outs, out)
	}
	return outs, nil
}

type dataGetter interface {
	GetData() []byte
}

func publicKeyFromAPI(d dataGetter) (any, error) {
	return x509.ParsePKIXPublicKey(d.GetData())
}

func publicKeyToAPI(d any) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(d)
}
