package ahocorasick

import (
	"math"
)

type byteClassRepresentatives struct {
	classes   *byteClasses
	bbyte     int
	lastClass *byte
}

func (b *byteClassRepresentatives) next() *byte {
	for b.bbyte < 256 {
		bbyte := byte(b.bbyte)
		class := b.classes.bytes[bbyte]
		b.bbyte += 1

		if b.lastClass == nil || *b.lastClass != class {
			c := class
			b.lastClass = &c
			return &bbyte
		}
	}
	return nil
}

type byteClassBuilder []bool

func (b byteClassBuilder) setRange(start, end byte) {
	if start > 0 {
		b[int(start)-1] = true
	}
	b[int(end)] = true
}

func (b byteClassBuilder) build() byteClasses {
	var classes byteClasses
	var class byte
	i := 0
	for {
		classes.bytes[byte(i)] = class
		if i >= 255 {
			break
		}
		if b[i] {
			if class == math.MaxUint8 {
				panic("shit happens")
			}
			class += 1
		}
		i += 1
	}
	return classes
}

func newByteClassBuilder() byteClassBuilder {
	return make([]bool, 256)
}

type byteClasses struct {
	bytes [256]byte
}

func singletons() byteClasses {
	var bc byteClasses
	for i := range bc.bytes {
		bc.bytes[i] = byte(i)
	}
	return bc
}

func (b byteClasses) alphabetLen() int {
	return int(b.bytes[255]) + 1
}

func (b byteClasses) isSingleton() bool {
	return b.alphabetLen() == 256
}
