package audio

import (
	"testing"

	"github.com/praetorian-inc/augustus/internal/probes/multimodal"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func TestAudioProbesRegistered(t *testing.T) {
	names := []string{
		"audio.VoiceJailbreakTTS", "audio.MultiAudioJailLang",
		"audio.BestOfN", "audio.JailbreakBenchEdit", "audio.Ultrasonic",
	}
	for _, name := range names {
		p, err := probes.Registry.Create(name, nil)
		if err != nil {
			t.Errorf("create %s: %v", name, err)
			continue
		}
		if p.Name() != name {
			t.Errorf("Name() = %q, want %q", p.Name(), name)
		}
		mm, ok := p.(multimodal.MultimodalProbe)
		if !ok {
			t.Errorf("%s does not implement multimodal.MultimodalProbe", name)
			continue
		}
		if got := len(mm.GetAudio()); got < 1 {
			t.Errorf("%s: GetAudio() len = %d, want >= 1", name, got)
		}
		meta, ok := p.(types.ProbeMetadata)
		if !ok {
			t.Errorf("%s does not implement types.ProbeMetadata", name)
			continue
		}
		if meta.GetPrimaryDetector() != "multimodal.AudioTranscribe" {
			t.Errorf("%s: PrimaryDetector = %q, want %q", name, meta.GetPrimaryDetector(), "multimodal.AudioTranscribe")
		}
	}
}

func TestBestOfN_HonorsNConfig(t *testing.T) {
	p, err := probes.Registry.Create("audio.BestOfN", map[string]any{"n": 2})
	if err != nil {
		t.Fatal(err)
	}
	mm, ok := p.(multimodal.MultimodalProbe)
	if !ok {
		t.Fatal("audio.BestOfN does not implement multimodal.MultimodalProbe")
	}
	if got := len(mm.GetAudio()); got != 2 {
		t.Errorf("with n=2: GetAudio() len = %d, want 2", got)
	}

	def, err := probes.Registry.Create("audio.BestOfN", nil)
	if err != nil {
		t.Fatal(err)
	}
	mmDef, ok := def.(multimodal.MultimodalProbe)
	if !ok {
		t.Fatal("audio.BestOfN does not implement multimodal.MultimodalProbe")
	}
	if got := len(mmDef.GetAudio()); got != 4 {
		t.Errorf("with default config: GetAudio() len = %d, want 4", got)
	}
}

func TestBestOfN_ClampsNConfig(t *testing.T) {
	tooMany, err := probes.Registry.Create("audio.BestOfN", map[string]any{"n": 10})
	if err != nil {
		t.Fatal(err)
	}
	mmMany, ok := tooMany.(multimodal.MultimodalProbe)
	if !ok {
		t.Fatal("audio.BestOfN does not implement multimodal.MultimodalProbe")
	}
	if got := len(mmMany.GetAudio()); got != 4 {
		t.Errorf("with n=10: GetAudio() len = %d, want clamped to 4", got)
	}

	tooFew, err := probes.Registry.Create("audio.BestOfN", map[string]any{"n": 0})
	if err != nil {
		t.Fatal(err)
	}
	mmFew, ok := tooFew.(multimodal.MultimodalProbe)
	if !ok {
		t.Fatal("audio.BestOfN does not implement multimodal.MultimodalProbe")
	}
	if got := len(mmFew.GetAudio()); got != 1 {
		t.Errorf("with n=0: GetAudio() len = %d, want clamped to 1", got)
	}
}
