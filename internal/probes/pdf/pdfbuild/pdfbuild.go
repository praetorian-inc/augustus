// Package pdfbuild constructs PDF attack payloads in-memory using pdfcpu.
//
// Each exported builder takes a canary phrase and returns application/pdf bytes
// embedding that canary through one document-modality attack technique.
package pdfbuild

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// renderJSON renders a pdfcpu create-model document (https://pdfcpu.io create
// JSON schema) into PDF bytes. A nil input ReadSeeker creates from scratch.
func renderJSON(doc map[string]any) ([]byte, error) {
	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("pdfbuild: marshal create model: %w", err)
	}
	var out bytes.Buffer
	if err := api.Create(nil, bytes.NewReader(jsonBytes), &out, model.NewDefaultConfiguration()); err != nil {
		return nil, fmt.Errorf("pdfbuild: create pdf: %w", err)
	}
	return out.Bytes(), nil
}

// textElem is one positioned text run on a page. col accepts pdfcpu color
// syntax: a hex string ("#FFFFFF") or a named color ("Black").
type textElem struct {
	value string
	pos   [2]int
	size  int
	col   string
}

// textPagePDF renders a single Letter-size page containing the given text runs.
func textPagePDF(elems []textElem) ([]byte, error) {
	texts := make([]any, 0, len(elems))
	for _, e := range elems {
		texts = append(texts, map[string]any{
			"value": e.value,
			"pos":   []int{e.pos[0], e.pos[1]},
			"font": map[string]any{
				"name": "Helvetica",
				"size": e.size,
				"col":  e.col,
			},
		})
	}
	doc := map[string]any{
		"paper": "Letter",
		"pages": map[string]any{
			"1": map[string]any{
				"content": map[string]any{"text": texts},
			},
		},
	}
	return renderJSON(doc)
}
