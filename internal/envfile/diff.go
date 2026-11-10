package envfile

import (
	"bytes"
	"slices"
)

// Changes lists variable names that differ between two files, each sorted.
// It never holds values.
type Changes struct {
	Added   []string // in the newer file only
	Removed []string // in the older file only
	Changed []string // in both, with different values
}

// Diff compares two .env files and reports which variables were added,
// removed or changed. A value counts as changed if its text after "="
// differs at all, including quoting or a trailing comment on an unquoted
// value: the files are never interpreted, so "the same text" is the only
// sameness there is. Values themselves never leave this function.
func Diff(older, newer []byte) (Changes, error) {
	a, err := scan(older)
	if err != nil {
		return Changes{}, err
	}
	b, err := scan(newer)
	if err != nil {
		return Changes{}, err
	}
	before := make(map[string][]byte, len(a))
	for _, e := range a {
		before[e.name] = e.value
	}
	var ch Changes
	for _, e := range b {
		old, ok := before[e.name]
		switch {
		case !ok:
			ch.Added = append(ch.Added, e.name)
		case !bytes.Equal(old, e.value):
			ch.Changed = append(ch.Changed, e.name)
		}
		delete(before, e.name)
	}
	for name := range before {
		ch.Removed = append(ch.Removed, name)
	}
	sortAll(&ch)
	return ch, nil
}

// NameChanges reports the names added and removed between two name lists,
// such as the ones Parse returns. Changed is always empty: names alone
// can't show that a value changed.
func NameChanges(older, newer []string) Changes {
	set := func(list []string) map[string]bool {
		m := make(map[string]bool, len(list))
		for _, n := range list {
			m[n] = true
		}
		return m
	}
	was, is := set(older), set(newer)
	var ch Changes
	for _, n := range newer {
		if !was[n] {
			ch.Added = append(ch.Added, n)
		}
	}
	for _, n := range older {
		if !is[n] {
			ch.Removed = append(ch.Removed, n)
		}
	}
	sortAll(&ch)
	return ch
}

func sortAll(ch *Changes) {
	slices.Sort(ch.Added)
	slices.Sort(ch.Removed)
	slices.Sort(ch.Changed)
}
