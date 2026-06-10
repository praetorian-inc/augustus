package ahocorasick

import (
	"unsafe"
)

type iDFA struct {
	atom automaton
}

func (d iDFA) MatchKind() *matchKind {
	return d.atom.MatchKind()
}

func (d iDFA) StartState() stateID {
	return d.atom.StartState()
}

func (d iDFA) MaxPatternLen() int {
	return d.atom.Repr().max_pattern_len
}

func (d iDFA) PatternCount() int {
	return d.atom.Repr().pattern_count
}

func (d iDFA) Prefilter() prefilter {
	return d.atom.Prefilter()
}

func (d iDFA) UsePrefilter() bool {
	p := d.Prefilter()
	if p == nil {
		return false
	}
	return !p.LooksForNonStartOfMatch()
}

func (d iDFA) OverlappingFindAt(prestate *prefilterState, haystack []byte, at int, state_id *stateID, match_index *int) *Match {
	return overlappingFindAt(d.atom, prestate, haystack, at, state_id, match_index)
}

func (d iDFA) EarliestFindAt(prestate *prefilterState, haystack []byte, at int, state_id *stateID) *Match {
	return earliestFindAt(d.atom, prestate, haystack, at, state_id)
}

func (d iDFA) FindAtNoState(prestate *prefilterState, haystack []byte, at int) *Match {
	return findAtNoState(d.atom, prestate, haystack, at)
}

func (n iDFA) LeftmostFindAtNoState(prestate *prefilterState, haystack []byte, at int) *Match {
	return leftmostFindAtNoState(n.atom, prestate, haystack, at)
}

type iDFABuilder struct {
	premultiply  bool
	byte_classes bool
}

func (d *iDFABuilder) build(nfa *iNFA) iDFA {
	var byteClasses byteClasses
	if d.byte_classes {
		byteClasses = nfa.byteClasses
	} else {
		byteClasses = singletons()
	}

	alphabet_len := byteClasses.alphabetLen()
	trans := make([]stateID, alphabet_len*len(nfa.states))
	for i := range trans {
		trans[i] = failedStateID
	}

	matches := make([][]pattern, len(nfa.states))
	var p prefilter

	if nfa.prefil != nil {
		p = nfa.prefil.clone()
	}

	rep := iRepr{
		match_kind:      nfa.matchKind,
		anchored:        nfa.anchored,
		premultiplied:   false,
		start_id:        nfa.startID,
		max_pattern_len: nfa.maxPatternLen,
		pattern_count:   nfa.patternCount,
		state_count:     len(nfa.states),
		max_match:       failedStateID,
		heap_bytes:      0,
		prefilter:       p,
		byte_classes:    byteClasses,
		trans:           trans,
		matches:         matches,
	}

	for id := 0; id < len(nfa.states); id += 1 {
		rep.matches[id] = append(rep.matches[id], nfa.states[id].matches...)
		fail := nfa.states[id].fail

		nfa.iterAllTransitions(&byteClasses, stateID(id), func(tr *next) {
			if tr.id == failedStateID {
				tr.id = nfaNextStateMemoized(nfa, &rep, stateID(id), fail, tr.key)
			}
			rep.setNextState(stateID(id), tr.key, tr.id)
		})

	}

	rep.shuffleMatchStates()
	rep.calculateSize()

	if d.premultiply {
		rep.premultiply()
		if byteClasses.isSingleton() {
			return iDFA{&iPremultiplied{rep}}
		} else {
			return iDFA{&iPremultipliedByteClass{&rep}}
		}
	}
	if byteClasses.isSingleton() {
		return iDFA{&iStandard{rep}}
	}
	return iDFA{&iByteClass{&rep}}
}

type iByteClass struct {
	repr *iRepr
}

func (p iByteClass) FindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return findAtNoState(p, prefilterState, bytes, i)
}

func (p iByteClass) Repr() *iRepr {
	return p.repr
}

func (p iByteClass) MatchKind() *matchKind {
	return &p.repr.match_kind
}

func (p iByteClass) Anchored() bool {
	return p.repr.anchored
}

func (p iByteClass) Prefilter() prefilter {
	return p.repr.prefilter
}

func (p iByteClass) StartState() stateID {
	return p.repr.start_id
}

func (b iByteClass) IsValid(id stateID) bool {
	return int(id) < b.repr.state_count
}

func (b iByteClass) IsMatchState(id stateID) bool {
	return b.repr.isMatchState(id)
}

func (b iByteClass) IsMatchOrDeadState(id stateID) bool {
	return b.repr.isMatchStateOrDeadState(id)
}

func (b iByteClass) GetMatch(id stateID, i int, i2 int) *Match {
	return b.repr.GetMatch(id, i, i2)
}

func (b iByteClass) MatchCount(id stateID) int {
	return b.repr.MatchCount(id)
}

func (b iByteClass) NextState(id stateID, b2 byte) stateID {
	alphabet_len := b.repr.byte_classes.alphabetLen()
	input := b.repr.byte_classes.bytes[b2]
	o := int(id)*alphabet_len + int(input)
	return b.repr.trans[o]
}

func (p iByteClass) NextStateNoFail(id stateID, b byte) stateID {
	next := p.NextState(id, b)
	if next == failedStateID {
		panic("automaton should never return fail_id for next state")
	}
	return next
}

func (p iByteClass) StandardFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return standardFindAt(&p, prefilterState, bytes, i, id)
}

func (p iByteClass) StandardFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return standardFindAtImp(&p, prefilterState, prefilter, bytes, i, id)
}

func (p iByteClass) LeftmostFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAt(&p, prefilterState, bytes, i, id)
}

func (p iByteClass) LeftmostFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAtImp(&p, prefilterState, prefilter, bytes, i, id)
}

func (p iByteClass) LeftmostFindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return leftmostFindAtNoState(&p, prefilterState, bytes, i)
}

func (p iByteClass) LeftmostFindAtNoStateImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int) *Match {
	return leftmostFindAtNoStateImp(&p, prefilterState, prefilter, bytes, i)
}

func (p iByteClass) OverlappingFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID, i2 *int) *Match {
	return overlappingFindAt(&p, prefilterState, bytes, i, id, i2)
}

func (p iByteClass) EarliestFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return earliestFindAt(&p, prefilterState, bytes, i, id)
}

func (p iByteClass) FindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return findAt(&p, prefilterState, bytes, i, id)
}

type iPremultipliedByteClass struct {
	repr *iRepr
}

func (p iPremultipliedByteClass) FindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return findAtNoState(p, prefilterState, bytes, i)
}

func (p iPremultipliedByteClass) Repr() *iRepr {
	return p.repr
}

func (p iPremultipliedByteClass) MatchKind() *matchKind {
	return &p.repr.match_kind
}

func (p iPremultipliedByteClass) Anchored() bool {
	return p.repr.anchored
}

func (p iPremultipliedByteClass) Prefilter() prefilter {
	return p.repr.prefilter
}

func (p iPremultipliedByteClass) StartState() stateID {
	return p.repr.start_id
}

func (p iPremultipliedByteClass) IsValid(id stateID) bool {
	return (int(id) / p.repr.alphabetLen()) < p.repr.state_count
}

func (p iPremultipliedByteClass) IsMatchState(id stateID) bool {
	return p.repr.isMatchState(id)
}

func (p iPremultipliedByteClass) IsMatchOrDeadState(id stateID) bool {
	return p.repr.isMatchStateOrDeadState(id)
}

func (p iPremultipliedByteClass) GetMatch(id stateID, match_index int, end int) *Match {
	if id > p.repr.max_match {
		return nil
	}

	m := p.repr.matches[int(id)/p.repr.alphabetLen()][match_index]
	return &Match{
		pattern: m.PatternID,
		len:     m.PatternLength,
		end:     end,
	}
}

func (p iPremultipliedByteClass) MatchCount(id stateID) int {
	o := int(id) / p.repr.alphabetLen()
	return len(p.repr.matches[o])
}

func (p iPremultipliedByteClass) NextState(id stateID, b byte) stateID {
	input := p.repr.byte_classes.bytes[b]
	o := int(id) + int(input)
	return p.repr.trans[o]
}

// todo this leaks garbage
func (p iPremultipliedByteClass) NextStateNoFail(id stateID, b byte) stateID {
	next := p.NextState(id, b)
	if next == failedStateID {
		panic("automaton should never return fail_id for next state")
	}
	return next
}

func (p iPremultipliedByteClass) StandardFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return standardFindAt(&p, prefilterState, bytes, i, id)
}

func (p iPremultipliedByteClass) StandardFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return standardFindAtImp(&p, prefilterState, prefilter, bytes, i, id)
}

func (p iPremultipliedByteClass) LeftmostFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAt(&p, prefilterState, bytes, i, id)
}

func (p iPremultipliedByteClass) LeftmostFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAtImp(&p, prefilterState, prefilter, bytes, i, id)
}

func (p iPremultipliedByteClass) LeftmostFindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return leftmostFindAtNoState(&p, prefilterState, bytes, i)
}

func (p iPremultipliedByteClass) LeftmostFindAtNoStateImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int) *Match {
	return leftmostFindAtNoStateImp(&p, prefilterState, prefilter, bytes, i)
}

func (p iPremultipliedByteClass) OverlappingFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID, i2 *int) *Match {
	return overlappingFindAt(&p, prefilterState, bytes, i, id, i2)
}

func (p iPremultipliedByteClass) EarliestFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return earliestFindAt(&p, prefilterState, bytes, i, id)
}

func (p iPremultipliedByteClass) FindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return findAt(&p, prefilterState, bytes, i, id)
}

type iPremultiplied struct {
	repr iRepr
}

func (p iPremultiplied) FindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return findAtNoState(p, prefilterState, bytes, i)
}

func (p iPremultiplied) Repr() *iRepr {
	return &p.repr
}

func (p iPremultiplied) MatchKind() *matchKind {
	return &p.repr.match_kind
}

func (p iPremultiplied) Anchored() bool {
	return p.repr.anchored
}

func (p iPremultiplied) Prefilter() prefilter {
	return p.repr.prefilter
}

func (p iPremultiplied) StartState() stateID {
	return p.repr.start_id
}

func (p iPremultiplied) IsValid(id stateID) bool {
	return int(id)/256 < p.repr.state_count
}

func (p iPremultiplied) IsMatchState(id stateID) bool {
	return p.repr.isMatchState(id)
}

func (p iPremultiplied) IsMatchOrDeadState(id stateID) bool {
	return p.repr.isMatchStateOrDeadState(id)
}

func (p iPremultiplied) GetMatch(id stateID, match_index int, end int) *Match {
	if id > p.repr.max_match {
		return nil
	}
	m := p.repr.matches[int(id)/256][match_index]
	return &Match{
		pattern: m.PatternID,
		len:     m.PatternLength,
		end:     end,
	}
}

func (p iPremultiplied) MatchCount(id stateID) int {
	return len(p.repr.matches[int(id)/256])
}

func (p iPremultiplied) NextState(id stateID, b byte) stateID {
	o := int(id) + int(b)
	return p.repr.trans[o]
}

func (p iPremultiplied) NextStateNoFail(id stateID, b byte) stateID {
	next := p.NextState(id, b)
	if next == failedStateID {
		panic("automaton should never return fail_id for next state")
	}
	return next
}

func (p iPremultiplied) StandardFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return standardFindAt(&p, prefilterState, bytes, i, id)
}

func (p iPremultiplied) StandardFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return standardFindAtImp(&p, prefilterState, prefilter, bytes, i, id)
}

func (p iPremultiplied) LeftmostFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAt(&p, prefilterState, bytes, i, id)
}

func (p iPremultiplied) LeftmostFindAtImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAtImp(&p, prefilterState, prefilter, bytes, i, id)
}

func (p iPremultiplied) LeftmostFindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return leftmostFindAtNoState(&p, prefilterState, bytes, i)
}

func (p iPremultiplied) LeftmostFindAtNoStateImp(prefilterState *prefilterState, prefilter prefilter, bytes []byte, i int) *Match {
	return leftmostFindAtNoStateImp(&p, prefilterState, prefilter, bytes, i)
}

func (p iPremultiplied) OverlappingFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID, i2 *int) *Match {
	return overlappingFindAt(&p, prefilterState, bytes, i, id, i2)
}

func (p iPremultiplied) EarliestFindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return earliestFindAt(&p, prefilterState, bytes, i, id)
}

func (p iPremultiplied) FindAt(prefilterState *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return findAt(&p, prefilterState, bytes, i, id)
}

func nfaNextStateMemoized(nfa *iNFA, dfa *iRepr, populating stateID, current stateID, input byte) stateID {
	for {
		if current < populating {
			return dfa.nextState(current, input)
		}

		next := nfa.states[current].nextState(input)

		if next != failedStateID {
			return next
		}
		current = nfa.states[current].fail
	}
}

func newDFABuilder() *iDFABuilder {
	return &iDFABuilder{
		premultiply:  true,
		byte_classes: true,
	}
}

type iStandard struct {
	repr iRepr
}

func (p iStandard) FindAtNoState(prefilterState *prefilterState, bytes []byte, i int) *Match {
	return findAtNoState(&p, prefilterState, bytes, i)
}

func (p iStandard) Repr() *iRepr {
	return &p.repr
}

func (s *iStandard) MatchKind() *matchKind {
	return &s.repr.match_kind
}

func (s *iStandard) Anchored() bool {
	return s.repr.anchored
}

func (s *iStandard) Prefilter() prefilter {
	return s.repr.prefilter
}

func (s *iStandard) StartState() stateID {
	return s.repr.start_id
}

func (s *iStandard) IsValid(id stateID) bool {
	return int(id) < s.repr.state_count
}

func (s *iStandard) IsMatchState(id stateID) bool {
	return s.repr.isMatchState(id)
}

func (s *iStandard) IsMatchOrDeadState(id stateID) bool {
	return s.repr.isMatchStateOrDeadState(id)
}

func (s *iStandard) GetMatch(id stateID, match_index int, end int) *Match {
	return s.repr.GetMatch(id, match_index, end)
}

func (s *iStandard) MatchCount(id stateID) int {
	return s.repr.MatchCount(id)
}

func (s *iStandard) NextState(current stateID, input byte) stateID {
	o := int(current)*256 + int(input)
	return s.repr.trans[o]
}

func (s *iStandard) NextStateNoFail(id stateID, b byte) stateID {
	next := s.NextState(id, b)
	if next == failedStateID {
		panic("automaton should never return fail_id for next state")
	}
	return next
}

func (s *iStandard) StandardFindAt(state *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return standardFindAt(s, state, bytes, i, id)
}

func (s *iStandard) StandardFindAtImp(state *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return standardFindAtImp(s, state, prefilter, bytes, i, id)
}

func (s *iStandard) LeftmostFindAt(state *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAt(s, state, bytes, i, id)
}

func (s *iStandard) LeftmostFindAtImp(state *prefilterState, prefilter prefilter, bytes []byte, i int, id *stateID) *Match {
	return leftmostFindAtImp(s, state, prefilter, bytes, i, id)
}

func (s *iStandard) LeftmostFindAtNoState(state *prefilterState, bytes []byte, i int) *Match {
	return leftmostFindAtNoState(s, state, bytes, i)
}

func (s *iStandard) LeftmostFindAtNoStateImp(state *prefilterState, prefilter prefilter, bytes []byte, i int) *Match {
	return leftmostFindAtNoStateImp(s, state, prefilter, bytes, i)
}

func (s *iStandard) OverlappingFindAt(state *prefilterState, bytes []byte, i int, id *stateID, i2 *int) *Match {
	return overlappingFindAt(s, state, bytes, i, id, i2)
}

func (s *iStandard) EarliestFindAt(state *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return earliestFindAt(s, state, bytes, i, id)
}

func (s *iStandard) FindAt(state *prefilterState, bytes []byte, i int, id *stateID) *Match {
	return findAt(s, state, bytes, i, id)
}

type iRepr struct {
	match_kind      matchKind
	anchored        bool
	premultiplied   bool
	start_id        stateID
	max_pattern_len int
	pattern_count   int
	state_count     int
	max_match       stateID
	heap_bytes      int
	prefilter       prefilter
	byte_classes    byteClasses
	trans           []stateID
	matches         [][]pattern
}

func (r *iRepr) premultiply() {
	if r.premultiplied || r.state_count <= 1 {
		return
	}
	alpha_len := r.alphabetLen()

	for id := 2; id < r.state_count; id++ {
		offset := id * alpha_len
		slice := r.trans[offset : offset+alpha_len]
		for i := range slice {
			if slice[i] == deadStateID {
				continue
			}
			slice[i] = stateID(int(slice[i]) * alpha_len)
		}
	}
	r.premultiplied = true
	r.start_id = stateID(int(r.start_id) * alpha_len)
	r.max_match = stateID(int(r.max_match) * alpha_len)
}

func (r *iRepr) setNextState(from stateID, b byte, to stateID) {
	alphabet_len := r.alphabetLen()
	b = r.byte_classes.bytes[b]
	r.trans[int(from)*alphabet_len+int(b)] = to
}

func (r *iRepr) alphabetLen() int {
	return r.byte_classes.alphabetLen()
}

func (r *iRepr) nextState(from stateID, b byte) stateID {
	alphabet_len := r.alphabetLen()
	b = r.byte_classes.bytes[b]
	return r.trans[int(from)*alphabet_len+int(b)]
}

func (r *iRepr) isMatchState(id stateID) bool {
	return id <= r.max_match && id > deadStateID
}

func (r *iRepr) isMatchStateOrDeadState(id stateID) bool {
	return id <= r.max_match
}

func (r *iRepr) GetMatch(id stateID, match_index int, end int) *Match {
	i := int(id)
	if id > r.max_match {
		return nil
	}
	if i > len(r.matches) {
		return nil
	}
	matches := r.matches[int(id)]
	if match_index > len(matches) {
		return nil
	}
	pattern := matches[match_index]

	return &Match{
		pattern: pattern.PatternID,
		len:     pattern.PatternLength,
		end:     end,
	}
}

func (r *iRepr) MatchCount(id stateID) int {
	return len(r.matches[id])
}

func (r *iRepr) swapStates(id1 stateID, id2 stateID) {
	if r.premultiplied {
		panic("cannot shuffle match states of premultiplied iDFA")
	}

	o1 := int(id1) * r.alphabetLen()
	o2 := int(id2) * r.alphabetLen()

	for b := 0; b < r.alphabetLen(); b++ {
		r.trans[o1+b], r.trans[o2+b] = r.trans[o2+b], r.trans[o1+b]
	}
	r.matches[int(id1)], r.matches[int(id2)] = r.matches[int(id2)], r.matches[int(id1)]
}

func (r *iRepr) calculateSize() {
	intSize := int(unsafe.Sizeof(stateID(1)))
	size := (len(r.trans) * intSize) + (len(r.matches) * (intSize * 3))

	for _, state_matches := range r.matches {
		size += len(state_matches) * (intSize * 2)
	}
	var hb int
	if r.prefilter != nil {
		hb = r.prefilter.HeapBytes()
	}
	size += hb
	r.heap_bytes = size
}

func (r *iRepr) shuffleMatchStates() {
	if r.premultiplied {
		panic("cannot shuffle match states of premultiplied iDFA")
	}

	if r.state_count <= 1 {
		return
	}

	first_non_match := int(r.start_id)
	for first_non_match < r.state_count && len(r.matches[first_non_match]) > 0 {
		first_non_match += 1
	}
	swaps := make([]stateID, r.state_count)

	for i := range swaps {
		swaps[i] = failedStateID
	}

	cur := r.state_count - 1

	for cur > first_non_match {
		if len(r.matches[cur]) > 0 {
			r.swapStates(stateID(cur), stateID(first_non_match))
			swaps[cur] = stateID(first_non_match)
			swaps[first_non_match] = stateID(cur)

			first_non_match += 1
			for first_non_match < cur && len(r.matches[first_non_match]) > 0 {
				first_non_match += 1
			}
		}
		cur -= 1
	}

	for id := 0; id < r.state_count; id++ {
		alphabet_len := r.alphabetLen()
		offset := id * alphabet_len

		slice := r.trans[offset : offset+alphabet_len]

		for i := range slice {
			if swaps[slice[i]] != failedStateID {
				slice[i] = swaps[slice[i]]
			}
		}
	}

	if swaps[r.start_id] != failedStateID {
		r.start_id = swaps[r.start_id]
	}
	r.max_match = stateID(first_non_match - 1)
}

type pattern struct {
	PatternID     int
	PatternLength int
}
