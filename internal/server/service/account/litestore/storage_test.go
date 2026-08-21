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
    id              text    not null,
    aid             text    not null,
    token_hash      blob    not null,
    created_at_ns   integer not null,
    expires_at_ns   integer not null,
    last_used_at_ns integer not null,
    constraint refresh_tokens_pk primary key (id)
);

create table if not exists denylist
(
    token_id      text    not null primary key,
    aid           text    not null,
    expires_at_ns integer not null,
    created_at_ns integer not null,
    reason        text    not null
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
		ID: "token-id-1", AID: "account-1", TokenHash: []byte("01234567890123456789012345678901"),
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastUsedAt: now,
	}
}

// TestDeleteRefreshTokenIsSingleUse proves the refresh flow's rotation is
// enforced: consuming a refresh token succeeds once, and a replay reports the
// row as missing so no new session can be minted from it.
func TestDeleteRefreshTokenIsSingleUse(t *testing.T) {
	storage, ctx := newRefreshTokenStorage(t)

	rt := sampleRefreshToken()
	td.Require(t).CmpNoError(storage.CreateRefreshToken(ctx, rt), "create refresh token")

	td.CmpNoError(t, storage.DeleteRefreshToken(ctx, rt.TokenHash), "first delete consumes the token")
	td.Cmp(t, storage.DeleteRefreshToken(ctx, rt.TokenHash), account.ErrRefreshTokenNotFound,
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
	td.Cmp(t, storage.DeleteRefreshToken(ctx, rt.TokenHash), account.ErrRefreshTokenNotFound,
		"retained refresh token cannot mint a new session after sign-out")
}

func TestRevokeSessionRollsBackDenylistWhenRefreshDeleteFails(t *testing.T) {
	storage, ctx := newRefreshTokenStorage(t)

	rt := sampleRefreshToken()
	td.Require(t).CmpNoError(storage.CreateRefreshToken(ctx, rt), "create refresh token")
	_, err := storage.db.ExecContext(ctx, `
		CREATE TRIGGER fail_refresh_delete
		BEFORE DELETE ON refresh_tokens
		BEGIN
			SELECT RAISE(ABORT, 'injected refresh delete failure');
		END`)
	td.Require(t).CmpNoError(err, "install injected failure")

	err = storage.RevokeSession(ctx, account.DeniedToken{
		TokenID: rt.ID, AID: rt.AID, ExpiresAt: rt.ExpiresAt,
		CreatedAt: rt.CreatedAt, Reason: "logout",
	})
	if err == nil {
		t.Fatal("RevokeSession() unexpectedly succeeded")
	}

	var denied, refresh int
	td.Require(t).CmpNoError(
		storage.db.QueryRowContext(ctx, `SELECT count(*) FROM denylist WHERE token_id = ?`, rt.ID).Scan(&denied),
		"count denied token",
	)
	td.Require(t).CmpNoError(
		storage.db.QueryRowContext(ctx, `SELECT count(*) FROM refresh_tokens WHERE id = ?`, rt.ID).Scan(&refresh),
		"count refresh token",
	)
	if denied != 0 || refresh != 1 {
		t.Fatalf("partial revocation state = denied %d refresh %d, want 0/1", denied, refresh)
	}
}
