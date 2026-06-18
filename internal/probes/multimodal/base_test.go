package multimodal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

func TestImage_Creation(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		base64   string
		mimeType string
		path     string
	}{
		{
			name:     "image with data",
			data:     []byte("fake-image-data"),
			mimeType: "image/png",
		},
		{
			name:     "image with base64",
			base64:   "iVBORw0KGgoAAAANSUhEUgAAAAUA",
			mimeType: "image/jpeg",
		},
		{
			name:     "image with path",
			path:     "/path/to/image.jpg",
			mimeType: "image/jpeg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := attempt.Image{
				Data:     tt.data,
				Base64:   tt.base64,
				MimeType: tt.mimeType,
				Path:     tt.path,
			}

			assert.Equal(t, tt.data, img.Data)
			assert.Equal(t, tt.base64, img.Base64)
			assert.Equal(t, tt.mimeType, img.MimeType)
			assert.Equal(t, tt.path, img.Path)
		})
	}
}

func TestAudio_Creation(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		base64   string
		mimeType string
		duration time.Duration
	}{
		{
			name:     "audio with data",
			data:     []byte("fake-audio-data"),
			mimeType: "audio/mp3",
			duration: 5 * time.Second,
		},
		{
			name:     "audio with base64",
			base64:   "SUQzBAAAAAAAI1RTU0UAAAAPAAADTGF2ZjU4Ljc2LjEwMAAAAAAAAAAAAAAA",
			mimeType: "audio/wav",
			duration: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audio := attempt.Audio{
				Data:     tt.data,
				Base64:   tt.base64,
				MimeType: tt.mimeType,
				Duration: tt.duration,
			}

			assert.Equal(t, tt.data, audio.Data)
			assert.Equal(t, tt.base64, audio.Base64)
			assert.Equal(t, tt.mimeType, audio.MimeType)
			assert.Equal(t, tt.duration, audio.Duration)
		})
	}
}

// MockMultimodalProbe is a test implementation of MultimodalProbe
type MockMultimodalProbe struct {
	name        string
	description string
	goal        string
	detector    string
	prompts     []string
	images      []attempt.Image
	audio       []attempt.Audio
}

func (m *MockMultimodalProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	return nil, nil
}

func (m *MockMultimodalProbe) Name() string {
	return m.name
}

func (m *MockMultimodalProbe) Description() string {
	return m.description
}

func (m *MockMultimodalProbe) Goal() string {
	return m.goal
}

func (m *MockMultimodalProbe) GetPrimaryDetector() string {
	return m.detector
}

func (m *MockMultimodalProbe) GetPrompts() []string {
	return m.prompts
}

func (m *MockMultimodalProbe) GetImages() []attempt.Image {
	return m.images
}

func (m *MockMultimodalProbe) GetDocuments() []attempt.Document {
	return nil
}

func (m *MockMultimodalProbe) GetAudio() []attempt.Audio {
	return m.audio
}

func TestMultimodalProbe_Interface(t *testing.T) {
	t.Run("implements MultimodalProbe interface", func(t *testing.T) {
		images := []attempt.Image{
			{Path: "/test/image.png", MimeType: "image/png"},
		}
		audio := []attempt.Audio{
			{Path: "/test/audio.mp3", MimeType: "audio/mp3", Duration: 2 * time.Second},
		}

		probe := &MockMultimodalProbe{
			name:        "test.Multimodal",
			description: "Test multimodal probe",
			goal:        "Test multimodal attacks",
			detector:    "multimodal.Detector",
			prompts:     []string{"test prompt"},
			images:      images,
			audio:       audio,
		}

		// Verify it implements the interface
		var _ MultimodalProbe = probe

		// Test interface methods
		assert.Equal(t, "test.Multimodal", probe.Name())
		assert.Equal(t, "Test multimodal probe", probe.Description())
		assert.Equal(t, "Test multimodal attacks", probe.Goal())
		assert.Equal(t, "multimodal.Detector", probe.GetPrimaryDetector())
		assert.Equal(t, []string{"test prompt"}, probe.GetPrompts())
		assert.Len(t, probe.GetImages(), 1)
		assert.Len(t, probe.GetAudio(), 1)
	})

	t.Run("GetImages returns correct images", func(t *testing.T) {
		images := []attempt.Image{
			{Data: []byte("img1"), MimeType: "image/png"},
			{Base64: "base64data", MimeType: "image/jpeg"},
		}

		probe := &MockMultimodalProbe{
			images: images,
		}

		gotImages := probe.GetImages()
		assert.Len(t, gotImages, 2)
		assert.Equal(t, "image/png", gotImages[0].MimeType)
		assert.Equal(t, "image/jpeg", gotImages[1].MimeType)
	})

	t.Run("GetAudio returns correct audio", func(t *testing.T) {
		audio := []attempt.Audio{
			{Data: []byte("audio1"), MimeType: "audio/wav", Duration: 1 * time.Second},
		}

		probe := &MockMultimodalProbe{
			audio: audio,
		}

		gotAudio := probe.GetAudio()
		assert.Len(t, gotAudio, 1)
		assert.Equal(t, "audio/wav", gotAudio[0].MimeType)
		assert.Equal(t, 1*time.Second, gotAudio[0].Duration)
	})
}
