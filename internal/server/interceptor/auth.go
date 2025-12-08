package interceptor

import (
	"context"
	"strings"

	"github.com/plainq/plainq/internal/server/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// UserContextKey is the key for storing user claims in context
	UserContextKey contextKey = "user"
)

// AuthInterceptor creates a gRPC unary interceptor for authentication
func AuthInterceptor(authService *auth.AuthService) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Extract metadata from context
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		// Get authorization header
		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization header")
		}

		authHeader := authHeaders[0]

		// Check if it's a Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization header format")
		}

		token := parts[1]

		// Validate token
		claims, err := authService.ValidateToken(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
		}

		// Add claims to context
		ctx = context.WithValue(ctx, UserContextKey, claims)

		// Call the handler
		return handler(ctx, req)
	}
}

// OptionalAuthInterceptor creates a gRPC unary interceptor for optional authentication
func OptionalAuthInterceptor(authService *auth.AuthService) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return handler(ctx, req)
		}

		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return handler(ctx, req)
		}

		authHeader := authHeaders[0]
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return handler(ctx, req)
		}

		token := parts[1]
		claims, err := authService.ValidateToken(ctx, token)
		if err != nil {
			return handler(ctx, req)
		}

		ctx = context.WithValue(ctx, UserContextKey, claims)
		return handler(ctx, req)
	}
}

// GetClaimsFromContext extracts claims from the gRPC context
func GetClaimsFromContext(ctx context.Context) (*auth.Claims, bool) {
	claims, ok := ctx.Value(UserContextKey).(*auth.Claims)
	return claims, ok
}
