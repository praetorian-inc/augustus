package audio

import "embed"

//go:embed data/*.wav
var audioData embed.FS
