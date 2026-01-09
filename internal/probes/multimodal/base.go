// Package multimodal provides base types and interfaces for multimodal probes.
//
// Multimodal probes test LLMs with combined text, image, and audio inputs.
// This enables testing vulnerabilities that require non-text data.
package multimodal

import (
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// MultimodalProbe extends the Prober interface with multimodal capabilities.
//
// Probes implementing this interface can provide image and audio attachments
// in addition to text prompts. This enables testing of vulnerabilities that
// exploit multimodal input processing.
type MultimodalProbe interface {
	// Prober embeds the standard probe interface.
	probes.Prober

	// GetImages returns the image attachments used by this probe.
	GetImages() []attempt.Image

	// GetAudio returns the audio attachments used by this probe.
	GetAudio() []attempt.Audio
}
