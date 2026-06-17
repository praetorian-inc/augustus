package multimodal

import "embed"

//go:embed data/*/*.png data/*/*.jpg
var assetData embed.FS
