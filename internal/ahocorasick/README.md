# aho-corasick

Efficient string matching in Golang via the aho-corasick algorithm.

x20 faster than https://github.com/cloudflare/ahocorasick and x3 faster than https://github.com/anknown/ahocorasick

Memory consuption is a eigth of https://github.com/cloudflare/ahocorasick and half of https://github.com/anknown/ahocorasick

This library is forked from https://github.com/petar-dambovaliev/aho-corasick, which was heavily inspired by https://github.com/BurntSushi/aho-corasick.

## Usage

```bash
go get -u github.com/pgavlin/aho-corasick
```

```go
import (
    ahocorasick "github.com/pgavlin/aho-corasick"
)
builder := ahocorasick.NewAhoCorasickBuilder(Opts{
    AsciiCaseInsensitive: true,
    MatchOnlyWholeWords:  true,
    MatchKind:            LeftMostLongestMatch,
    DFA:                  true,
})

ac := builder.Build([]string{"bear", "masha"})
haystack := "The Bear and Masha"
matches := ac.FindAll(haystack)

for _, match := range matches {
    println(haystack[match.Start():match.End()])
}
```

Matching can be done via `NFA` or `DFA`.
`NFA` has runtime complexity O(N + M) in relation to the haystack and number of matches.
`DFA` has runtime complexity O(N), but it uses more memory.

Replacing of matches in the haystack.

`replaceWith` needs to be the same length as the `patterns`
```go
r := ahocorasick.NewReplacer(ac)
replaced := r.ReplaceAll(haystack, replaceWith)
```

`ReplaceAllFunc` is useful, for example, if you want to use the original text cassing but you are matching
case insensitively. You can replace partially by return false and from that point, the original string will be preserved.
```go
replaced := r.ReplaceAllFunc(haystack, func(match Match) (string, bool) {
    return `<a>` + haystack[match.Start():match.End()] + `<\a>`, true
})
```

Search for matches one at a time via the iterator

```go
iter := ac.Iter(haystack)

for next := iter.Next(); next != nil; next = iter.Next() {
    ...
}
```

It's plenty fast but if you want to use it in parallel, that is also possible.

Memory consumption won't increase because the read-only automaton is not actually copied, only the counters are.

The magic line is `ac := ac`

```go
var w sync.WaitGroup

w.Add(50)
for i := 0; i < 50; i++ {
    go func() {
        ac := ac
        matches := ac.FindAll(haystack)
        println(len(matches))
        w.Done()
    }()
}
w.Wait()
```
