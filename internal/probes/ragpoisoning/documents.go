package ragpoisoning

// Document represents a RAG document with metadata.
type Document struct {
	// Title is the document's title
	Title string
	// Content is the document's body text
	Content string
	// Metadata contains additional document properties (e.g., source, date, confidence)
	Metadata map[string]string
}
