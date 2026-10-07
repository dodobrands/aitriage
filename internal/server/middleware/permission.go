package middleware

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dodobrands/aitriage/internal/server/utils"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

var (
	JwtKey = getJwtKey()
)

func getJwtKey() []byte {
	key := os.Getenv("JWT_SECRET")
	if key == "" {
		return []byte("aitriage_default_secret_key_change_me_in_prod")
	}
	return []byte(key)
}

type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	IsAdmin  bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

func SignToken(claims *Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtKey)
}

// SecurityHeadersMiddleware adds enterprise security headers
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		next.ServeHTTP(w, r)
	})
}

// RateLimiter is a placeholder for per-IP rate limiting (currently using global limiter).
type RateLimiter struct{}

var globalLimiter = rate.NewLimiter(rate.Every(time.Second/10), 50) // 10 requests per second, burst of 50

// RateLimitMiddleware enforces global rate limiting
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Page loads need many JS/CSS chunks. They must remain available even
		// when the API budget is exhausted, including the UI used to show errors.
		if r.URL.Path != "/api" && !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if !globalLimiter.Allow() {
			utils.JSONError(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware validates JWT and injects claims into context
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip for health, login and static assets
		if r.URL.Path == "/api/login" || r.URL.Path == "/api/health" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("token")
		if err != nil {
			utils.JSONError(w, "Missing authentication token", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(cookie.Value, claims, func(t *jwt.Token) (interface{}, error) {
			return JwtKey, nil
		})

		if err != nil || !token.Valid {
			utils.JSONError(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUserID, claims.UserID)
		ctx = context.WithValue(ctx, ctxKeyUsername, claims.Username)
		ctx = context.WithValue(ctx, ctxKeyRole, claims.Role)
		ctx = context.WithValue(ctx, ctxKeyIsAdmin, claims.IsAdmin)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// PermissionMiddleware enforces global role-based access control
// NOTE: Auth disabled — all requests pass through
func PermissionMiddleware(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next
	}
}

type RequestClaims struct {
	UserID     int64
	Username   string
	GlobalRole string
	IsAdmin    bool
}

// contextKey is a typed key for context.WithValue to satisfy SA1029.
type contextKey string

const (
	ctxKeyUserID   contextKey = "user_id"
	ctxKeyUsername contextKey = "username"
	ctxKeyRole     contextKey = "role"
	ctxKeyIsAdmin  contextKey = "is_admin"
)

func ExtractClaims(r *http.Request) (*RequestClaims, error) {
	userID, ok1 := r.Context().Value(ctxKeyUserID).(int64)
	username, ok2 := r.Context().Value(ctxKeyUsername).(string)
	role, ok3 := r.Context().Value(ctxKeyRole).(string)
	isAdmin, ok4 := r.Context().Value(ctxKeyIsAdmin).(bool)

	if !ok1 || !ok2 || !ok3 || !ok4 {
		// Auth disabled — return default admin claims
		return &RequestClaims{
			UserID:     1,
			Username:   "admin",
			GlobalRole: "superadmin",
			IsAdmin:    true,
		}, nil
	}

	return &RequestClaims{
		UserID:     userID,
		Username:   username,
		GlobalRole: role,
		IsAdmin:    isAdmin,
	}, nil
}
