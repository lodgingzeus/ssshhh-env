package commands

import (
	"errors"
	"regexp"
	"strings"
)

// DefaultEnv is the environment used when a target names only a project.
const DefaultEnv = "default"

// nameRe is the form of project and environment names. It keeps them safe
// to print, to log and to use as an audit target.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var errBadTarget = errors.New("invalid name: use 1-63 lowercase letters, digits or '-', starting with a letter or digit")

// ValidName reports whether s is an acceptable project or environment name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Target is a project and one of its environments.
type Target struct {
	Project string
	Env     string
}

// ParseTarget parses "project" or "project:env". Without an environment it
// means DefaultEnv.
func ParseTarget(s string) (Target, error) {
	project, env, hasEnv := strings.Cut(s, ":")
	if !hasEnv {
		env = DefaultEnv
	}
	if !ValidName(project) || !ValidName(env) {
		return Target{}, errBadTarget
	}
	return Target{Project: project, Env: env}, nil
}

// String returns the target as "project:env".
func (t Target) String() string { return t.Project + ":" + t.Env }
