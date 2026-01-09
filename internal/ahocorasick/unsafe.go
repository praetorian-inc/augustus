package ahocorasick

import (
	"reflect"
	"unsafe"
)

func unsafeBytes[T Text](s T) []byte {
	if reflect.TypeFor[T]().Kind() == reflect.String {
		return unsafe.Slice(unsafe.StringData(string(s)), len(s))
	}
	return []byte(s)
}

func unsafeText[T Text](s []byte) T {
	if reflect.TypeFor[T]().Kind() == reflect.String {
		return T(unsafe.String(unsafe.SliceData(s), len(s)))
	}
	return T(s)
}
