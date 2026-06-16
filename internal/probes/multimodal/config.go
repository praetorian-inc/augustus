package multimodal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// resolveAsset builds a probe's image + canary from optional config, falling
// back to the embedded default asset and default canary. Config keys (all
// optional):
//   - "image" (alias "image_path"): filesystem path to a custom image; when set,
//     it replaces the embedded default.
//   - "canary": custom canary phrase; when set, it replaces the default. It is
//     attached to the attempt (MultimodalPrompt.Canary) so the detector matches it.
//   - "mime_type": MIME for a custom image; when omitted it is inferred from the
//     file extension (.png->image/png, .jpg/.jpeg->image/jpeg, .gif->image/gif,
//     .webp->image/webp). For the embedded default, MIME is the passed default.
func resolveAsset(cfg registry.Config, embeddedPath, defaultMime, defaultCanary string) (attempt.Image, string, error) {
	canary := defaultCanary
	if c := registry.GetString(cfg, "canary", ""); c != "" {
		canary = c
	}

	imagePath := registry.GetString(cfg, "image", "")
	if imagePath == "" {
		imagePath = registry.GetString(cfg, "image_path", "")
	}

	if imagePath != "" {
		// imagePath is operator-supplied probe configuration (the "image" /
		// "image_path" config key), intentionally letting an engineer point a
		// probe at their own file. It is at the same trust level as the CLI
		// invocation — the operator already has their own filesystem access —
		// so no privilege boundary is crossed and an allowlist would only break
		// the feature. filepath.Clean is applied for hygiene.
		data, err := os.ReadFile(filepath.Clean(imagePath)) // #nosec G304 -- operator-supplied, trusted probe config path
		if err != nil {
			return attempt.Image{}, "", fmt.Errorf("reading custom image %q: %w", imagePath, err)
		}

		mime := registry.GetString(cfg, "mime_type", "")
		if mime == "" {
			mime = mimeFromExt(imagePath)
		}
		if mime == "" {
			return attempt.Image{}, "", fmt.Errorf("cannot infer MIME type for custom image %q: set %q in config", imagePath, "mime_type")
		}

		return attempt.Image{Data: data, MimeType: mime}, canary, nil
	}

	data, err := assetData.ReadFile(embeddedPath)
	if err != nil {
		return attempt.Image{}, "", fmt.Errorf("loading embedded asset %q: %w", embeddedPath, err)
	}

	return attempt.Image{Data: data, MimeType: defaultMime}, canary, nil
}

// mimeFromExt infers an image MIME type from a file path extension. It returns
// "" for unrecognized extensions so callers can require an explicit mime_type.
func mimeFromExt(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	default:
		return ""
	}
}
