package ahocorasick

import (
	"bytes"
	"iter"
	"sync"
	"unicode"
)

type Text interface {
	~[]byte | ~string
}

type findIter struct {
	fsm                 imp
	prestate            *prefilterState
	haystack            []byte
	pos                 int
	matchOnlyWholeWords bool
}

func newFindIter(ac AhoCorasick, haystack []byte) findIter {
	prestate := prefilterState{
		skips:       0,
		skipped:     0,
		maxMatchLen: ac.i.MaxPatternLen(),
		inert:       false,
		lastScanAt:  0,
	}

	return findIter{
		fsm:                 ac.i,
		prestate:            &prestate,
		haystack:            haystack,
		pos:                 0,
		matchOnlyWholeWords: ac.matchOnlyWholeWords,
	}
}

// Next gives a pointer to the next match yielded by the iterator or nil, if there is none
func (f *findIter) Next() *Match {
	for {
		if f.pos > len(f.haystack) {
			return nil
		}

		result := f.fsm.FindAtNoState(f.prestate, f.haystack, f.pos)

		if result == nil {
			return nil
		}

		f.pos = result.end - result.len + 1

		if f.matchOnlyWholeWords {
			if result.Start()-1 >= 0 && (unicode.IsLetter(rune(f.haystack[result.Start()-1])) || unicode.IsDigit(rune(f.haystack[result.Start()-1]))) {
				continue
			}
			if result.end < len(f.haystack) && (unicode.IsLetter(rune(f.haystack[result.end])) || unicode.IsDigit(rune(f.haystack[result.end]))) {
				continue
			}
		}
		return result
	}
}

type overlappingIter struct {
	fsm                 imp
	prestate            *prefilterState
	haystack            []byte
	pos                 int
	stateID             stateID
	matchIndex          int
	matchOnlyWholeWords bool
}

func (f *overlappingIter) Next() *Match {
	for {
		if f.pos > len(f.haystack) {
			return nil
		}

		result := f.fsm.OverlappingFindAt(f.prestate, f.haystack, f.pos, &f.stateID, &f.matchIndex)

		if result == nil {
			return nil
		}

		f.pos = result.End()

		if f.matchOnlyWholeWords {
			if result.Start()-1 >= 0 && (unicode.IsLetter(rune(f.haystack[result.Start()-1])) || unicode.IsDigit(rune(f.haystack[result.Start()-1]))) {
				continue
			}
			if result.end < len(f.haystack) && (unicode.IsLetter(rune(f.haystack[result.end])) || unicode.IsDigit(rune(f.haystack[result.end]))) {
				continue
			}
		}

		return result
	}
}

func newOverlappingIter(ac AhoCorasick, haystack []byte) overlappingIter {
	prestate := prefilterState{
		skips:       0,
		skipped:     0,
		maxMatchLen: ac.i.MaxPatternLen(),
		inert:       false,
		lastScanAt:  0,
	}
	return overlappingIter{
		fsm:                 ac.i,
		prestate:            &prestate,
		haystack:            haystack,
		pos:                 0,
		stateID:             ac.i.StartState(),
		matchIndex:          0,
		matchOnlyWholeWords: ac.matchOnlyWholeWords,
	}
}

// AhoCorasick is the main data structure that does most of the work
type AhoCorasick struct {
	i                   imp
	matchKind           matchKind
	matchOnlyWholeWords bool
}

func (ac AhoCorasick) PatternCount() int {
	return ac.i.PatternCount()
}

// Iter gives an iterator over the built patterns
func Iter[T Text](ac AhoCorasick, haystack T) iter.Seq[*Match] {
	i := newFindIter(ac, unsafeBytes(haystack))
	return func(yield func(*Match) bool) {
		for m := i.Next(); m != nil; m = i.Next() {
			if !yield(m) {
				break
			}
		}
	}
}

// IterOverlapping gives an iterator over the built patterns with overlapping matches
func IterOverlapping[T Text](ac AhoCorasick, haystack T) iter.Seq[*Match] {
	if ac.matchKind != StandardMatch {
		panic("only StandardMatch allowed for overlapping matches")
	}
	iter := newOverlappingIter(ac, unsafeBytes(haystack))
	return func(yield func(*Match) bool) {
		for m := iter.Next(); m != nil; m = iter.Next() {
			if !yield(m) {
				break
			}
		}
	}
}

// FindAll returns the matches found in the haystack
func FindAll[T Text](ac AhoCorasick, haystack T) []Match {
	iter := newFindIter(ac, unsafeBytes(haystack))

	var matches []Match
	for {
		next := iter.Next()
		if next == nil {
			break
		}

		matches = append(matches, *next)
	}

	return matches
}

var pool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

// ReplaceAllFunc replaces the matches found in the haystack according to the user provided function
// it gives fine grained control over what is replaced.
// A user can chose to stop the replacing process early by returning false in the lambda
// In that case, everything from that point will be kept as the original haystack
func ReplaceAllFunc[T, U Text](ac AhoCorasick, haystack T, f func(match Match) (U, bool)) T {
	return replaceAll(ac, haystack, func(_ []Match) int { return -1 }, f)
}

// ReplaceAll replaces the matches found in the haystack according to the user provided slice `replaceWith`
// It panics, if `replaceWith` has length different from the patterns that it was built with
func ReplaceAll[T, U Text](ac AhoCorasick, haystack T, replaceWith []U) T {
	if len(replaceWith) != ac.PatternCount() {
		panic("replaceWith needs to have the same length as the pattern count")
	}

	return replaceAll(
		ac,
		haystack,
		func(matches []Match) int {
			size, start := 0, 0
			for _, m := range matches {
				size += m.Start() - start + len(replaceWith[m.pattern])
				start = m.Start() + m.len
			}
			if start-1 < len(haystack) {
				size += len(haystack[start:])
			}
			return size
		},
		func(match Match) (U, bool) {
			return replaceWith[match.pattern], true
		},
	)
}

// ReplaceAllWith replaces the matches found in the haystack according with replacement.
func ReplaceAllWith[T, U Text](ac AhoCorasick, haystack T, replacement U) T {
	return replaceAll(
		ac,
		haystack,
		func(matches []Match) int {
			size, start := 0, 0
			for _, m := range matches {
				size += m.Start() - start + len(replacement)
				start = m.Start() + m.len
			}
			if start-1 < len(haystack) {
				size += len(haystack[start:])
			}
			return size
		},
		func(match Match) (U, bool) {
			return replacement, true
		},
	)
}

func replaceAll[T, U Text](ac AhoCorasick, haystack T, measure func(matches []Match) int, f func(match Match) (U, bool)) T {
	matches := FindAll(ac, haystack)
	if len(matches) == 0 {
		return haystack
	}

	str := pool.Get().(*bytes.Buffer)
	defer func() {
		str.Reset()
		pool.Put(str)
	}()

	// right-size the buffer
	switch size := measure(matches); size {
	case 0:
		var zero T
		return zero
	case -1:
		// do nothing
	default:
		str.Grow(size)
	}

	haystackBytes := unsafeBytes(haystack)

	start := 0
	for _, match := range matches {
		rw, ok := f(match)
		if !ok {
			str.Write(haystackBytes[start:])
			return unsafeText[T](str.Bytes())
		}
		str.Write(haystackBytes[start:match.Start()])
		str.Write(unsafeBytes(rw))
		start = match.Start() + match.len
	}

	if start-1 < len(haystack) {
		str.Write(haystackBytes[start:])
	}

	return unsafeText[T](str.Bytes())
}

// AhoCorasickBuilder defines a set of options applied before the patterns are built
type AhoCorasickBuilder struct {
	dfaBuilder          *iDFABuilder
	nfaBuilder          *iNFABuilder
	dfa                 bool
	matchOnlyWholeWords bool
}

// Opts defines a set of options applied before the patterns are built
// MatchOnlyWholeWords does filtering after matching with MatchKind
// this could lead to situations where, in this case, nothing is matched
//
//	    trieBuilder := NewAhoCorasickBuilder(Opts{
//		     MatchOnlyWholeWords: true,
//		     MatchKind:           LeftMostLongestMatch,
//		     DFA:                 false,
//	    })
//
//			trie := trieBuilder.Build([]string{"testing", "testing 123"})
//			result := trie.FindAll("testing 12345")
//		 len(result) == 0
//
// this is due to the fact LeftMostLongestMatch is the matching strategy
// "testing 123" is found but then is filtered out by MatchOnlyWholeWords
// use MatchOnlyWholeWords with caution
type Opts struct {
	AsciiCaseInsensitive bool
	MatchOnlyWholeWords  bool
	MatchKind            matchKind
	DFA                  bool
	// ByteEquivalence defines custom byte equivalences for matching.
	// When set, for each byte b in patterns, the automaton will also
	// transition on all bytes returned by ByteEquivalence(b).
	// This enables "klingon" support - custom encodings/transformations.
	// If nil, no byte equivalences are applied (standard matching).
	ByteEquivalence func(byte) []byte
}

// NewAhoCorasickBuilder creates a new AhoCorasickBuilder based on Opts
func NewAhoCorasickBuilder(o Opts) AhoCorasickBuilder {
	return AhoCorasickBuilder{
		dfaBuilder:          newDFABuilder(),
		nfaBuilder:          newNFABuilder(o.MatchKind, o.AsciiCaseInsensitive, o.ByteEquivalence),
		dfa:                 o.DFA,
		matchOnlyWholeWords: o.MatchOnlyWholeWords,
	}
}

// Build builds a (non)deterministic finite automata from the user provided patterns
func (a *AhoCorasickBuilder) Build(patterns []string) AhoCorasick {
	bytePatterns := make([][]byte, len(patterns))
	for pati, pat := range patterns {
		bytePatterns[pati] = unsafeBytes(pat)
	}

	return a.BuildByte(bytePatterns)
}

// BuildByte builds a (non)deterministic finite automata from the user provided patterns
func (a *AhoCorasickBuilder) BuildByte(patterns [][]byte) AhoCorasick {
	nfa := a.nfaBuilder.build(patterns)
	match_kind := nfa.matchKind

	if a.dfa {
		dfa := a.dfaBuilder.build(nfa)
		return AhoCorasick{dfa, match_kind, a.matchOnlyWholeWords}
	}

	return AhoCorasick{nfa, match_kind, a.matchOnlyWholeWords}
}

type imp interface {
	MatchKind() *matchKind
	StartState() stateID
	MaxPatternLen() int
	PatternCount() int
	Prefilter() prefilter
	UsePrefilter() bool
	OverlappingFindAt(prestate *prefilterState, haystack []byte, at int, state_id *stateID, match_index *int) *Match
	EarliestFindAt(prestate *prefilterState, haystack []byte, at int, state_id *stateID) *Match
	FindAtNoState(prestate *prefilterState, haystack []byte, at int) *Match
}

type matchKind int

const (
	// Use standard match semantics, which support overlapping matches. When
	// used with non-overlapping matches, matches are reported as they are seen.
	StandardMatch matchKind = iota
	// Use leftmost-first match semantics, which reports leftmost matches.
	// When there are multiple possible leftmost matches, the match
	// corresponding to the pattern that appeared earlier when constructing
	// the automaton is reported.
	// This does **not** support overlapping matches or stream searching
	LeftMostFirstMatch
	// Use leftmost-longest match semantics, which reports leftmost matches.
	// When there are multiple possible leftmost matches, the longest match is chosen.
	LeftMostLongestMatch
)

func (m matchKind) isLeftmost() bool {
	return m == LeftMostFirstMatch || m == LeftMostLongestMatch
}

func (m matchKind) isLeftmostFirst() bool {
	return m == LeftMostFirstMatch
}

// A representation of a match reported by an Aho-Corasick automaton.
//
// A match has two essential pieces of information: the identifier of the
// pattern that matched, along with the start and end offsets of the match
// in the haystack.
type Match struct {
	pattern int
	len     int
	end     int
}

// Pattern returns the index of the pattern in the slice of the patterns provided by the user that
// was matched
func (m *Match) Pattern() int {
	return m.pattern
}

// End gives the index of the last character of this match inside the haystack
func (m *Match) End() int {
	return m.end
}

// Start gives the index of the first character of this match inside the haystack
func (m *Match) Start() int {
	return m.end - m.len
}

type stateID uint

const (
	failedStateID stateID = 0
	deadStateID   stateID = 1
)
