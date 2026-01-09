package ahocorasick

import (
	"sort"
	"unsafe"
)

type iNFA struct {
	matchKind     matchKind
	startID       stateID
	maxPatternLen int
	patternCount  int
	heapBytes     int
	prefil        prefilter
	anchored      bool
	byteClasses   byteClasses
	states        []state
}

func (n *iNFA) FindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return findAtNoState(n, prefilterState, bytes, i)
}

func (n *iNFA) Repr() *iRepr {
	return nil
}

func (n *iNFA) MatchKind() *matchKind {
	return &n.matchKind
}

func (n *iNFA) Anchored() bool {
	return n.anchored
}

func (n *iNFA) Prefilter() prefilter {
	return n.prefil
}

func (n *iNFA) StartState() stateID {
	return n.startID
}

func (n *iNFA) IsValid(id stateID) bool {
	return int(id) < len(n.states)
}

func (n *iNFA) IsMatchState(id stateID) bool {
	return n.state(id).isMatch()
}

func (n *iNFA) IsMatchOrDeadState(id stateID) bool {
	return isMatchOrDeadState(n, id)
}

func (n *iNFA) MatchCount(id stateID) int {
	return len(n.states[id].matches)
}

func (n *iNFA) NextState(id stateID, b byte) stateID {
	for {
		state := n.states[id]
		next := state.nextState(b)
		if next != failedStateID {
			return next
		}
		id = state.fail
	}
}

func (n *iNFA) NextStateNoFail(id stateID, b byte) stateID {
	next := n.NextState(id, b)
	if next == failedStateID {
		panic("automaton should never return fail_id for next state")
	}
	return next
}

func (n *iNFA) StandardFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return standardFindAt(n, prefilterState, bytes, i, id)
}

func (n *iNFA) StandardFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return standardFindAtImp(n, prefilterState, prefilter, bytes, i, id)
}

func (n *iNFA) LeftmostFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAt(n, prefilterState, bytes, i, id)
}

func (n *iNFA) LeftmostFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAtImp(n, prefilterState, prefilter, bytes, i, id)
}

func (n *iNFA) LeftmostFindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return leftmostFindAtNoState(n, prefilterState, bytes, i)
}

func (n *iNFA) LeftmostFindAtNoStateImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int) *Match {
	return leftmostFindAtNoStateImp(n, prefilterState, prefilter, bytes, i)
}

func (n *iNFA) OverlappingFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID, i2 *int) *Match {
	return overlappingFindAt(n, prefilterState, bytes, i, id, i2)
}

func (n *iNFA) EarliestFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return earliestFindAt(n, prefilterState, bytes, i, id)
}

func (n *iNFA) FindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return findAt(n, prefilterState, bytes, i, id)
}

func (n *iNFA) MaxPatternLen() int {
	return n.maxPatternLen
}

func (n *iNFA) PatternCount() int {
	return n.patternCount
}

func (n *iNFA) UsePrefilter() bool {
	p := n.Prefilter()
	if p == nil {
		return false
	}
	return !p.LooksForNonStartOfMatch()
}

func (n *iNFA) GetMatch(id stateID, matchIndex int, end int) *Match {
	if int(id) >= len(n.states) {
		return nil
	}
	state := n.states[id]
	if matchIndex >= len(state.matches) {
		return nil
	}
	pat := state.matches[matchIndex]
	return &Match{
		pattern: pat.PatternID,
		len:     pat.PatternLength,
		end:     end,
	}
}

func (n *iNFA) addDenseState(depth int) stateID {
	d := newDense()
	trans := transitions{dense: &d}
	id := stateID(len(n.states))

	fail := n.startID

	if n.anchored {
		fail = deadStateID
	}

	n.states = append(n.states, state{
		trans:   trans,
		fail:    fail,
		matches: nil,
		depth:   depth,
	})
	return id
}

func (n *iNFA) addSparseState(depth int) stateID {
	trans := transitions{sparse: &sparse{inner: nil}}
	id := stateID(len(n.states))

	fail := n.startID

	if n.anchored {
		fail = deadStateID
	}

	n.states = append(n.states, state{
		trans:   trans,
		fail:    fail,
		matches: nil,
		depth:   depth,
	})
	return id
}

func (n *iNFA) state(id stateID) *state {
	return &n.states[int(id)]
}

type compiler struct {
	builder          iNFABuilder
	prefilter        prefilterBuilder
	nfa              iNFA
	byteclassBuilder byteClassBuilder
}

func (c *compiler) compile(patterns [][]byte) *iNFA {
	c.addState(0)
	c.addState(0)
	c.addState(0)

	c.buildTrie(patterns)

	c.addStartStateLoop()
	c.addDeadStateLoop()

	if !c.builder.anchored {
		if c.builder.matchKind.isLeftmost() {
			c.fillFailureTransitionsLeftmost()
		} else {
			c.fillFailureTransitionsStandard()
		}
	}
	c.closeStartStateLoop()

	c.nfa.byteClasses = c.byteclassBuilder.build()
	if !c.builder.anchored {
		c.nfa.prefil = c.prefilter.build()
	}
	c.calculateSize()

	return &c.nfa
}

func (c *compiler) calculateSize() {
	var size int
	for _, state := range c.nfa.states {
		size += state.heapBytes()
	}

	c.nfa.heapBytes = size
}

func (c *compiler) closeStartStateLoop() {
	if c.builder.anchored || (c.builder.matchKind.isLeftmost() && c.nfa.state(c.nfa.startID).isMatch()) {
		startId := c.nfa.startID
		start := c.nfa.state(startId)

		for b := 0; b < 256; b++ {
			if start.nextState(byte(b)) == startId {
				start.setNextState(byte(b), deadStateID)
			}
		}
	}
}

type queuedState struct {
	id           stateID
	matchAtDepth *int
}

func startQueuedState(nfa *iNFA) queuedState {
	var matchAtDepth *int
	if nfa.states[nfa.startID].isMatch() {
		r := 0
		matchAtDepth = &r
	}
	return queuedState{id: nfa.startID, matchAtDepth: matchAtDepth}
}

func (q *queuedState) nextQueuedState(nfa *iNFA, id stateID) queuedState {
	nextMatchAtDepth := q.nextMatchAtDepth(nfa, id)
	return queuedState{id, nextMatchAtDepth}
}

func (q *queuedState) nextMatchAtDepth(
	nfa *iNFA,
	next stateID,
) *int {
	switch q.matchAtDepth {
	case nil:
		if !nfa.state(next).isMatch() {
			return nil
		}
	default:
		return q.matchAtDepth
	}

	depth := nfa.state(next).depth - *nfa.state(next).getLongestMatch() + 1
	return &depth
}

func (c *compiler) fillFailureTransitionsStandard() {
	queue := make([]stateID, 0)
	seen := c.queuedSet()

	for b := 0; b < 256; b++ {
		next := c.nfa.state(c.nfa.startID).nextState(byte(b))
		if next != c.nfa.startID {
			if !seen.contains(next) {
				queue = append(queue, next)
				seen.insert(next)
			}
		}
	}

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		it := newIterTransitions(&c.nfa, id)

		for next := it.next(); next != nil; next = it.next() {
			if seen.contains(next.id) {
				continue
			}
			queue = append(queue, next.id)
			seen.insert(next.id)

			fail := it.nfa.state(id).fail
			for it.nfa.state(fail).nextState(next.key) == failedStateID {
				fail = it.nfa.state(fail).fail
			}
			fail = it.nfa.state(fail).nextState(next.key)
			it.nfa.state(next.id).fail = fail
			it.nfa.copyMatches(fail, next.id)
		}
		it.nfa.copyEmptyMatches(id)
	}
}

func (c *compiler) fillFailureTransitionsLeftmost() {
	queue := make([]queuedState, 0)
	seen := c.queuedSet()
	start := startQueuedState(&c.nfa)

	for b := 0; b < 256; b++ {
		nextId := c.nfa.state(c.nfa.startID).nextState(byte(b))
		if nextId != start.id {
			next := start.nextQueuedState(&c.nfa, nextId)
			if !seen.contains(next.id) {
				queue = append(queue, next)
				seen.insert(next.id)
			}
			if c.nfa.state(nextId).isMatch() {
				c.nfa.state(nextId).fail = deadStateID
			}
		}
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		anyTrans := false
		it := newIterTransitions(&c.nfa, item.id)
		tr := it.next()
		for tr != nil {
			anyTrans = true
			next := item.nextQueuedState(it.nfa, tr.id)
			if seen.contains(next.id) {
				tr = it.next()
				continue
			}
			queue = append(queue, next)
			seen.insert(next.id)

			fail := it.nfa.state(item.id).fail
			for it.nfa.state(fail).nextState(tr.key) == failedStateID {
				fail = it.nfa.state(fail).fail
			}
			fail = it.nfa.state(fail).nextState(tr.key)

			if next.matchAtDepth != nil {
				failDepth := it.nfa.state(fail).depth
				nextDepth := it.nfa.state(next.id).depth
				if nextDepth-*next.matchAtDepth+1 > failDepth {
					it.nfa.state(next.id).fail = deadStateID
					tr = it.next()
					continue
				}

				if start.id == it.nfa.state(next.id).fail {
					panic("states that are match states or follow match states should never have a failure transition back to the start state in leftmost searching")
				}
			}
			it.nfa.state(next.id).fail = fail
			it.nfa.copyMatches(fail, next.id)
			tr = it.next()
		}
		if !anyTrans && it.nfa.state(item.id).isMatch() {
			it.nfa.state(item.id).fail = deadStateID
		}
	}
}

func (n *iNFA) copyEmptyMatches(dst stateID) {
	n.copyMatches(n.startID, dst)
}

func (n *iNFA) copyMatches(src stateID, dst stateID) {
	srcState, dstState := n.getTwo(src, dst)
	dstState.matches = append(dstState.matches, srcState.matches...)
}

func (n *iNFA) getTwo(i stateID, j stateID) (*state, *state) {
	if i == j {
		panic("src and dst should not be equal")
	}

	if i < j {
		before, after := n.states[0:j], n.states[j:]
		return &before[i], &after[0]
	}

	before, after := n.states[0:i], n.states[i:]
	return &after[0], &before[j]
}

func (n *iNFA) iterAllTransitions(byteClasses *byteClasses, id stateID, f func(tr *next)) {
	n.states[id].trans.iterAll(byteClasses, f)
}

func newIterTransitions(nfa *iNFA, stateId stateID) iterTransitions {
	return iterTransitions{
		nfa:     nfa,
		stateId: stateId,
		cur:     0,
	}
}

type iterTransitions struct {
	nfa     *iNFA
	stateId stateID
	cur     int
}

type next struct {
	key byte
	id  stateID
}

func (i *iterTransitions) next() *next {
	sparse := i.nfa.states[int(i.stateId)].trans.sparse
	if sparse != nil {
		if i.cur >= len(sparse.inner) {
			return nil
		}
		ii := i.cur
		i.cur += 1
		return &next{
			key: sparse.inner[ii].b,
			id:  sparse.inner[ii].s,
		}
	}

	dense := i.nfa.states[int(i.stateId)].trans.dense
	for i.cur < len(dense.inner) {
		if i.cur >= 256 {
			panic("There are always exactly 255 transitions in dense repr")
		}

		b := byte(i.cur)
		id := dense.inner[b]
		i.cur += 1
		if id != failedStateID {
			return &next{
				key: b,
				id:  id,
			}
		}
	}
	return nil
}

type queuedSet struct {
	set map[stateID]struct{}
	ind int
}

func newInertQueuedSet() queuedSet {
	return queuedSet{
		set: make(map[stateID]struct{}),
		ind: 0,
	}
}

func (q *queuedSet) contains(s stateID) bool {
	_, ok := q.set[s]
	return ok
}

func (q *queuedSet) insert(s stateID) {
	q.set[s] = struct{}{}
}

func newActiveQueuedSet() queuedSet {
	return queuedSet{
		set: make(map[stateID]struct{}, 0),
		ind: 0,
	}
}

func (c *compiler) queuedSet() queuedSet {
	if c.builder.asciiCaseInsensitive {
		return newActiveQueuedSet()
	}
	return newInertQueuedSet()
}

func (c *compiler) addStartStateLoop() {
	startId := c.nfa.startID
	start := c.nfa.state(startId)
	for b := 0; b < 256; b++ {
		if start.nextState(byte(b)) == failedStateID {
			start.setNextState(byte(b), startId)
		}
	}
}

func (c *compiler) addDeadStateLoop() {
	dead := c.nfa.state(deadStateID)
	for b := 0; b < 256; b++ {
		dead.setNextState(byte(b), deadStateID)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (c *compiler) buildTrie(patterns [][]byte) {

Patterns:
	for pati, pat := range patterns {
		c.nfa.maxPatternLen = max(c.nfa.maxPatternLen, len(pat))
		c.nfa.patternCount += 1

		prev := c.nfa.startID
		sawMatch := false

		for depth, b := range pat {
			sawMatch = sawMatch || c.nfa.state(prev).isMatch()
			if c.builder.matchKind.isLeftmostFirst() && sawMatch {
				continue Patterns
			}

			// Handle ByteEquivalence (klingon support) - takes precedence over AsciiCaseInsensitive
			if c.builder.byteEquivalence != nil {
				equivBytes := c.builder.byteEquivalence(b)
				for _, equiv := range equivBytes {
					c.byteclassBuilder.setRange(equiv, equiv)
				}

				// Check if any equivalent byte already has a transition
				next := failedStateID
				for _, equiv := range equivBytes {
					candidateNext := c.nfa.state(prev).nextState(equiv)
					if candidateNext != failedStateID {
						next = candidateNext
						break
					}
				}

				if next == failedStateID {
					next = c.addState(depth + 1)
				}

				// Always set transitions for ALL equivalent bytes
				for _, equiv := range equivBytes {
					c.nfa.state(prev).setNextState(equiv, next)
				}
				prev = next
			} else {
				// Original handling: direct byte + optional case insensitive
				c.byteclassBuilder.setRange(b, b)

				if c.builder.asciiCaseInsensitive {
					b := oppositeAsciiCase(b)
					c.byteclassBuilder.setRange(b, b)
				}

				next := c.nfa.state(prev).nextState(b)

				if next != failedStateID {
					prev = next
				} else {
					next := c.addState(depth + 1)
					c.nfa.state(prev).setNextState(b, next)
					if c.builder.asciiCaseInsensitive {
						b := oppositeAsciiCase(b)
						c.nfa.state(prev).setNextState(b, next)
					}
					prev = next
				}
			}
		}
		c.nfa.state(prev).addMatch(pati, len(pat))

		if c.builder.prefilter {
			c.prefilter.add(pat)
		}
	}
}

const asciiCaseMask byte = 0b0010_0000

func toAsciiLowercase(b byte) byte {
	return b | (1 * asciiCaseMask)
}

func toAsciiUpper(b byte) byte {
	b &= ^(1 * asciiCaseMask)
	return b
}

func oppositeAsciiCase(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return toAsciiLowercase(b)
	} else if 'a' <= b && b <= 'z' {
		return toAsciiUpper(b)
	}
	return b
}

func (c *compiler) addState(depth int) stateID {
	if depth < c.builder.denseDepth {
		return c.nfa.addDenseState(depth)

	}
	return c.nfa.addSparseState(depth)
}

func newCompiler(builder iNFABuilder) compiler {
	p := newPrefilterBuilder(builder.asciiCaseInsensitive)

	return compiler{
		builder:   builder,
		prefilter: p,
		nfa: iNFA{
			matchKind:     builder.matchKind,
			startID:       2,
			maxPatternLen: 0,
			patternCount:  0,
			heapBytes:     0,
			prefil:        nil,
			anchored:      builder.anchored,
			byteClasses:   singletons(),
			states:        nil,
		},
		byteclassBuilder: newByteClassBuilder(),
	}
}

type iNFABuilder struct {
	denseDepth           int
	matchKind            matchKind
	prefilter            bool
	anchored             bool
	asciiCaseInsensitive bool
	byteEquivalence      func(byte) []byte // klingon support
}

func newNFABuilder(kind matchKind, asciiCaseInsensitive bool, byteEquivalence func(byte) []byte) *iNFABuilder {
	// Disable prefilter when ByteEquivalence is used because the prefilter
	// doesn't account for equivalent bytes, causing matches to be missed.
	usePrefilter := byteEquivalence == nil

	return &iNFABuilder{
		denseDepth:           2,
		matchKind:            kind,
		prefilter:            usePrefilter,
		anchored:             false,
		asciiCaseInsensitive: asciiCaseInsensitive,
		byteEquivalence:      byteEquivalence,
	}
}

func (b *iNFABuilder) build(patterns [][]byte) *iNFA {
	c := newCompiler(*b)
	return c.compile(patterns)
}

type state struct {
	trans   transitions
	fail    stateID
	matches []pattern
	depth   int
}

func (s *state) heapBytes() int {
	var i int
	intSize := int(unsafe.Sizeof(i))
	return s.trans.heapBytes() + (len(s.matches) * (intSize * 2))
}

func (s *state) addMatch(patternID, patternLength int) {
	s.matches = append(s.matches, pattern{
		PatternID:     patternID,
		PatternLength: patternLength,
	})
}

func (s *state) isMatch() bool {
	return len(s.matches) > 0
}

func (s *state) getLongestMatch() *int {
	if len(s.matches) == 0 {
		return nil
	}
	longest := s.matches[0].PatternLength
	return &longest
}

func (s *state) nextState(input byte) stateID {
	return s.trans.nextState(input)
}

func (s *state) setNextState(input byte, next stateID) {
	s.trans.setNextState(input, next)
}

type transitions struct {
	sparse *sparse
	dense  *dense
}

func sparseIter(trans []innerSparse, f func(*next)) {
	var byte16 uint16

	for _, tr := range trans {
		for byte16 < uint16(tr.b) {
			f(&next{
				key: byte(byte16),
				id:  failedStateID,
			})
			byte16 += 1
		}
		f(&next{
			key: tr.b,
			id:  tr.s,
		})
		byte16 += 1
	}

	for b := byte16; b < 256; b++ {
		f(&next{
			key: byte(b),
			id:  failedStateID,
		})
	}
}

func (t *transitions) iterAll(byteClasses *byteClasses, f func(tr *next)) {
	if byteClasses.isSingleton() {
		if t.sparse != nil {
			sparseIter(t.sparse.inner, f)
		}

		if t.dense != nil {
			for b := 0; b < 256; b++ {
				f(&next{
					key: byte(b),
					id:  t.dense.inner[b],
				})
			}
		}
	} else {
		if t.sparse != nil {
			var lastClass *byte

			sparseIter(t.sparse.inner, func(n *next) {
				class := byteClasses.bytes[n.key]

				if lastClass == nil || *lastClass != class {
					cc := class
					lastClass = &cc
					f(n)
				}
			})
		}

		if t.dense != nil {
			bcr := byteClassRepresentatives{
				classes:   byteClasses,
				bbyte:     0,
				lastClass: nil,
			}

			for n := bcr.next(); n != nil; n = bcr.next() {
				f(&next{
					key: *n,
					id:  t.dense.inner[*n],
				})
			}
		}
	}

}

func (t *transitions) heapBytes() int {
	var i int
	intSize := int(unsafe.Sizeof(i))
	if t.sparse != nil {
		return len(t.sparse.inner) * (2 * intSize)
	}
	return len(t.dense.inner) * intSize
}

func (t *transitions) nextState(input byte) stateID {
	if t.sparse != nil {
		for _, sp := range t.sparse.inner {
			if sp.b == input {
				return sp.s
			}
		}
		return failedStateID
	}
	return t.dense.inner[input]
}

func (t *transitions) setNextState(input byte, next stateID) {
	if t.sparse != nil {
		idx := sort.Search(len(t.sparse.inner), func(i int) bool {
			return t.sparse.inner[i].b >= input
		})

		if idx < len(t.sparse.inner) && t.sparse.inner[idx].b == input {
			t.sparse.inner[idx].s = next
		} else {
			if len(t.sparse.inner) > 0 {
				is := innerSparse{
					b: input,
					s: next,
				}
				if idx == len(t.sparse.inner) {
					t.sparse.inner = append(t.sparse.inner, is)
				} else {
					t.sparse.inner = append(
						t.sparse.inner[:idx+1],
						t.sparse.inner[idx:]...)
					t.sparse.inner[idx] = is
				}
			} else {
				t.sparse.inner = []innerSparse{
					{
						b: input,
						s: next,
					},
				}
			}
		}
		return
	}
	t.dense.inner[int(input)] = next
}

func newDense() dense {
	return dense{inner: make([]stateID, 256)}
}

type dense struct {
	inner []stateID
}

type innerSparse struct {
	b byte
	s stateID
}

type sparse struct {
	inner []innerSparse
}
