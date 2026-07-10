package audio

import (
	"bytes"
	"testing"
)

func TestFixturesAreValidWAV(t *testing.T) {
	names := []string{
		"data/voice_jailbreak.wav", "data/multilang_en.wav", "data/multilang_es.wav",
		"data/multilang_fr.wav", "data/bestofn_00.wav", "data/bestofn_01.wav",
		"data/bestofn_02.wav", "data/bestofn_03.wav", "data/jailbreak_edit.wav",
		"data/ultrasonic.wav",
	}
	for _, n := range names {
		// Exercise the loader that audio.* probes will use (loadAudio), rather
		// than reading the embed.FS directly, so this test also guards the
		// loader's happy path.
		aud, err := loadAudio(n, "audio/wav")
		if err != nil {
			t.Errorf("missing fixture %s: %v", n, err)
			continue
		}
		b := aud.Data
		if len(b) < 44 || !bytes.HasPrefix(b, []byte("RIFF")) || !bytes.Contains(b[:16], []byte("WAVE")) {
			t.Errorf("%s is not a valid WAV (len=%d)", n, len(b))
		}
	}
}

func TestLoadAudioMissingFile(t *testing.T) {
	_, err := loadAudio("data/does_not_exist.wav", "audio/wav")
	if err == nil {
		t.Fatal("loadAudio on a missing file should return an error, got nil")
	}
}
