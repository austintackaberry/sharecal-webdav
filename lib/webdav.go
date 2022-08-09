package lib

import (
	"context"
	"net/http"
	"regexp"
	"strings"

	"fmt"
	"os"

	"encoding/base64"

	"github.com/nedpals/supabase-go"
	"go.uber.org/zap"
	"golang.org/x/net/webdav"
)

// CorsCfg is the CORS config.
type CorsCfg struct {
	Enabled        bool
	Credentials    bool
	AllowedHeaders []string
	AllowedHosts   []string
	AllowedMethods []string
	ExposedHeaders []string
}

// Config is the configuration of a WebDAV instance.
type Config struct {
	*User
	Auth           bool
	Debug          bool
	NoSniff        bool
	Cors           CorsCfg
	Users          map[string]*User
	LogFormat      string
	SupabaseClient *supabase.Client
}

// ServeHTTP determines if the request is for this plugin, and if all prerequisites are met.
func (c *Config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u := c.User
	requestOrigin := r.Header.Get("Origin")

	// Add CORS headers before any operation so even on a 401 unauthorized status, CORS will work.
	if c.Cors.Enabled && requestOrigin != "" {
		headers := w.Header()

		allowedHeaders := strings.Join(c.Cors.AllowedHeaders, ", ")
		allowedMethods := strings.Join(c.Cors.AllowedMethods, ", ")
		exposedHeaders := strings.Join(c.Cors.ExposedHeaders, ", ")

		allowAllHosts := len(c.Cors.AllowedHosts) == 1 && c.Cors.AllowedHosts[0] == "*"
		allowedHost := isAllowedHost(c.Cors.AllowedHosts, requestOrigin)

		if allowAllHosts {
			headers.Set("Access-Control-Allow-Origin", "*")
		} else if allowedHost {
			headers.Set("Access-Control-Allow-Origin", requestOrigin)
		}

		if allowAllHosts || allowedHost {
			headers.Set("Access-Control-Allow-Headers", allowedHeaders)
			headers.Set("Access-Control-Allow-Methods", allowedMethods)

			if c.Cors.Credentials {
				headers.Set("Access-Control-Allow-Credentials", "true")
			}

			if len(c.Cors.ExposedHeaders) > 0 {
				headers.Set("Access-Control-Expose-Headers", exposedHeaders)
			}
		}
	}

	if r.Method == "OPTIONS" && c.Cors.Enabled && requestOrigin != "" {
		return
	}

	// Authentication
	if c.Auth {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		// Gets the correct user for this request.
		username, password, ok := r.BasicAuth()
		zap.L().Info("login attempt", zap.String("username", username), zap.String("password", password), zap.String("remote_address", r.RemoteAddr))
		if !ok {
			http.Error(w, "Not authorized", 401)
			return
		}

		if username == "accessToken" {
			user, err := c.SupabaseClient.Auth.User(context.Background(), password)
			if err != nil {
				zap.L().Error("error auth access token", zap.Error(err))
				http.Error(w, "Not authorized", 401)
				return
			}
			username = user.Email
		} else {
			_, err := c.SupabaseClient.Auth.SignIn(context.Background(), supabase.UserCredentials{
				Email:    username,
				Password: password,
			})
			if err != nil {
				zap.L().Error("error auth username password", zap.Error(err))
				http.Error(w, "Not authorized", 401)
				return
			}
		}
		path := base64.RawURLEncoding.EncodeToString([]byte(username))
		zap.L().Info("encoded path", zap.String("path", path))
		_ = os.Mkdir(fmt.Sprintf("%s/%s", c.Scope, path), os.ModePerm)

		u = &User{
			Scope:  c.Scope,
			Modify: c.Modify,
			Rules: []*Rule{
				{Allow: true,
					Modify: false,
					Regexp: regexp.MustCompile(".*")},
				{Allow: true,
					Modify: true,
					Regexp: regexp.MustCompile(fmt.Sprintf("%s/%s.*", c.Scope, path))},
			},
			Handler: &webdav.Handler{
				Prefix: c.Handler.Prefix,
				FileSystem: WebDavDir{
					Dir:     webdav.Dir(c.Scope),
					NoSniff: c.NoSniff,
				},
				LockSystem: webdav.NewMemLS(),
			},
		}
		zap.L().Info("user authorized", zap.String("username", username))
	}

	// Checks for user permissions relatively to this PATH.
	noModification := r.Method == "GET" || r.Method == "HEAD" ||
		r.Method == "OPTIONS" || r.Method == "PROPFIND"

	allowed := u.Allowed(r.URL.Path, noModification)

	zap.L().Debug("allowed & method & path", zap.Bool("allowed", allowed), zap.String("method", r.Method), zap.String("path", r.URL.Path))

	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.Method == "HEAD" {
		w = newResponseWriterNoBody(w)
	}

	// Excerpt from RFC4918, section 9.4:
	//
	// 		GET, when applied to a collection, may return the contents of an
	//		"index.html" resource, a human-readable view of the contents of
	//		the collection, or something else altogether.
	//
	// Get, when applied to collection, will return the same as PROPFIND method.
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, u.Handler.Prefix) {
		info, err := u.Handler.FileSystem.Stat(context.TODO(), strings.TrimPrefix(r.URL.Path, u.Handler.Prefix))
		if err == nil && info.IsDir() {
			r.Method = "PROPFIND"

			if r.Header.Get("Depth") == "" {
				r.Header.Add("Depth", "1")
			}
		}
	}

	// Runs the WebDAV.
	//u.Handler.LockSystem = webdav.NewMemLS()
	u.Handler.ServeHTTP(w, r)
}

// responseWriterNoBody is a wrapper used to suprress the body of the response
// to a request. Mainly used for HEAD requests.
type responseWriterNoBody struct {
	http.ResponseWriter
}

// newResponseWriterNoBody creates a new responseWriterNoBody.
func newResponseWriterNoBody(w http.ResponseWriter) *responseWriterNoBody {
	return &responseWriterNoBody{w}
}

// Header executes the Header method from the http.ResponseWriter.
func (w responseWriterNoBody) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Write suprresses the body.
func (w responseWriterNoBody) Write(data []byte) (int, error) {
	return 0, nil
}

// WriteHeader writes the header to the http.ResponseWriter.
func (w responseWriterNoBody) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}
