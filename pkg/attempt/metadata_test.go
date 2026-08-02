package attempt

import "testing"

func TestMetaAudioOutputKey(t *testing.T) {
	if MetaAudioOutput != "audio_output" {
		t.Fatalf("MetaAudioOutput = %q, want %q", MetaAudioOutput, "audio_output")
	}
}
