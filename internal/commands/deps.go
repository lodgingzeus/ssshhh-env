package commands

import (
	"context"
	"log/slog"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// Store is the persistence the commands need. *store.Store implements it.
type Store interface {
	// Projects and versions.
	CreateProject(ctx context.Context, name string, creatorID int64, wrap func(projectID int64) (store.WrappedDEK, error)) (store.Project, error)
	ProjectByName(ctx context.Context, name string) (store.Project, error)
	EnvironmentNames(ctx context.Context, projectID int64) ([]string, error)
	AppendVersion(ctx context.Context, v store.NewVersion, seal func(envID, number int64) (store.SealedVersion, error)) (store.Version, error)
	LatestVersion(ctx context.Context, projectID int64, envName string) (store.Version, error)
	VersionByNumber(ctx context.Context, projectID int64, envName string, number int64) (store.Version, error)
	ListVersions(ctx context.Context, projectID int64, envName string, limit int) ([]store.VersionInfo, error)

	// Membership.
	MemberRole(ctx context.Context, projectID, userID int64) (string, error)
	AddMember(ctx context.Context, projectID, userID int64, role string, grantedBy int64) error
	SetMemberRole(ctx context.Context, projectID, userID int64, role string, grantedBy int64) error
	RemoveMember(ctx context.Context, projectID, userID int64) error
	ListMembers(ctx context.Context, projectID int64) ([]store.Member, error)
	ProjectsForUser(ctx context.Context, userID int64) ([]store.Membership, error)

	// Users and keys.
	CreateUser(ctx context.Context, u store.NewUser, keys []store.NewKey) (store.User, error)
	UserByName(ctx context.Context, name string) (store.User, error)
	UserByGitHubLogin(ctx context.Context, login string) (store.User, error)
	ListUsers(ctx context.Context) ([]store.UserSummary, error)
	DisableUser(ctx context.Context, userID int64) error
	KeysForUser(ctx context.Context, userID int64) ([]store.Key, error)
	AddKeys(ctx context.Context, userID int64, keys []store.NewKey) ([]string, error)
	RemoveKey(ctx context.Context, userID int64, fingerprint string) error
	ReplaceGitHubKeys(ctx context.Context, userID int64, keys []store.NewKey) (store.KeyChanges, error)
}

// KeyFetcher fetches a GitHub user's public keys. github.Client implements
// it. Keys are fetched only when a user is first added or when an admin
// asks for a refresh, never to authenticate anyone.
type KeyFetcher interface {
	Keys(ctx context.Context, login string) ([]gossh.PublicKey, error)
}

// Deps is what every command runs against. All fields are required.
type Deps struct {
	Store     Store
	MasterKey *crypto.MasterKey
	GitHub    KeyFetcher
	Log       *slog.Logger
}
