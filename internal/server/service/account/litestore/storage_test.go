package litestore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/service/account"
	"github.com/marsolab/servekit/dbkit/litekit"
	"github.com/maxatome/go-testdeep/td"
)

// refreshTokensSchema mirrors the refresh_tokens table from the migrations so
// the storage can be exercised against a real SQLite database.
const refreshTokensSchema = `
create table if not exists refresh_tokens
(
    id         text      not null,
    aid        text      not null,
    token      text      not null,
    created_at timestamp not null default current_timestamp,
    expires_at timestamp not null default current_timestamp,
    constraint refresh_tokens_pk primary key (id)
);
`

func newRefreshTokenStorage(t *testing.T) (*Storage, context.Context) {
	t.Helper()

	ctx := context.Background()

	conn, err := litekit.New(filepath.Join(t.TempDir(), "account.db"))
	td.Require(t).CmpNoError(err, "open database")
	t.Cleanup(func() { td.CmpNoError(t, conn.Close(), "close database") })

	_, err = conn.ExecContext(ctx, refreshTokensSchema)
	td.Require(t).CmpNoError(err, "create refresh_tokens table")

	storage, err := NewStorage(conn, nil)
	td.Require(t).CmpNoError(err, "create storage")

	return storage, ctx
}

func sampleRefreshToken() account.RefreshToken {
	now := time.Now()

	return account.RefreshToken{
		ID:        "token-id-1",
		AID:       "account-1",
		Token:     "refresh-token-string",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
}

// TestDeleteRefreshTokenIsSingleUse proves the refresh flow's rotation is
// enforced: consuming a refresh token succeeds once, and a replay reports the
// row as missing so no new session can be minted from it.
func TestDeleteRefreshTokenIsSingleUse(t *testing.T) {
	storage, ctx := newRefreshTokenStorage(t)

	rt := sampleRefreshToken()
	td.Require(t).CmpNoError(storage.CreateRefreshToken(ctx, rt), "create refresh token")

	td.CmpNoError(t, storage.DeleteRefreshToken(ctx, rt.Token), "first delete consumes the token")
	td.Cmp(t, storage.DeleteRefreshToken(ctx, rt.Token), account.ErrRefreshTokenNotFound,
		"replaying the consumed token is rejected")
}

// TestDeleteRefreshTokenByTokenIDRevokesRefresh mirrors sign-out: dropping the
// refresh row by its token id (shared with the access token) makes a later
// refresh with the retained token fail as no-longer-valid.
func TestDeleteRefreshTokenByTokenIDRevokesRefresh(t *testing.T) {
	storage, ctx := newRefreshTokenStorage(t)

	rt := sampleRefreshToken()
	td.Require(t).CmpNoError(storage.CreateRefreshToken(ctx, rt), "create refresh token")

	td.CmpNoError(t, storage.DeleteRefreshTokenByTokenID(ctx, rt.ID), "sign-out revokes the session's refresh token")
	td.Cmp(t, storage.DeleteRefreshToken(ctx, rt.Token), account.ErrRefreshTokenNotFound,
		"retained refresh token cannot mint a new session after sign-out")
}
