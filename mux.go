//Copyright (c) 2014 Tim Shannon
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in
//all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//THE SOFTWARE.

// TreeMux is almost entirely copied from the DefaultServeMux in net/http
// The difference is the ability to create a tree of muxes to handle different
// hierarchies of paths.
// A treemux has a child mux which handles muxing for all paths that don't
// match the parent mux, and only for paths one additional level deep
// /<parentMux>/<childMux>/
//
// The same "longest path wins" rule applies, except child paths
// won't be checked until longest parent paths are checked
//
// This is being used to handle dynamically added paths in the children
// For example.  If a path isn't predefined in the parent, then it's up to
// the child to determine if the path should 404 or not.
//
// No RegEx matching, just a hierarchy of muxers. This will hopefully
// allow for the simplicity and behavior of the DefaultMuxer, but
// with a little more added possibilities for muxing.
package treemux

import (
	"net/http"
	"path"
	"strings"
	"sync"
)

type Mux struct {
	mu       sync.RWMutex
	m        map[string]muxEntry
	hosts    bool // whether any patterns contain hostnames
	depth    int  // depth from root muxer, or how many parents
	childMux *Mux
}

type muxEntry struct {
	explicit bool
	h        http.Handler
	pattern  string
}

// NewServeMux allocates and returns a new TreeMux.
func NewServeMux() *Mux { return &Mux{m: make(map[string]muxEntry)} }

// SetChild sets a child muxer to handle any paths that don't match
// the parent
func (m *Mux) SetChild(childMux *Mux) {
	m.childMux = childMux
	childMux.depth = m.depth + 1
}

func (m *Mux) IsChild() bool {
	return m.depth > 0
}

// Root returns the root of the current mux
// If it's a child, this would be the value that doesn't match
// the parent mux
func (m *Mux) Root(r *http.Request) string {
	return root(r, m.depth)
}

func root(r *http.Request, depth int) string {
	path := r.URL.Path
	root := ""
	for i := 0; i < depth; i++ {
		root, path = splitRootAndPath(path)
	}

	return root

}

func splitRootAndPath(pattern string) (root, path string) {
	if pattern == "" {
		panic("treemux: invalid pattern " + pattern)
	}
	split := strings.SplitN(pattern[1:], "/", 2)
	root = split[0]
	if len(split) < 2 {
		path = "/"
	} else {
		path = "/" + split[1]
	}
	return root, path
}

// Does path match pattern?
func pathMatch(pattern, path string) bool {
	if len(pattern) == 0 {
		// should not happen
		return false
	}
	n := len(pattern)
	if pattern[n-1] != '/' {
		return pattern == path
	}
	return len(path) >= n && path[0:n] == pattern
}

// Return the canonical path for p, eliminating . and .. elements.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}
	return np
}

// Find a handler on a handler map given a path string
// Most-specific (longest) pattern wins
func (mux *Mux) match(path string) (h http.Handler, pattern string) {
	var n = 0
	for k, v := range mux.m {
		if !pathMatch(k, path) {
			continue
		}
		if h == nil || len(k) > n {
			n = len(k)
			h = v.h
			pattern = v.pattern
		}
	}
	return
}

// Handler returns the handler to use for the given request,
// consulting r.Method, r.Host, and r.URL.Path. It always returns
// a non-nil handler. If the path is not in its canonical form, the
// handler will be an internally-generated handler that redirects
// to the canonical path.
//
// Handler also returns the registered pattern that matches the
// request or, in the case of internally-generated redirects,
// the pattern that will match after following the redirect.
//
// If there is no registered handler that applies to the request,
// Handler returns a ``page not found'' handler and an empty pattern.
func (mux *Mux) Handler(r *http.Request) (h http.Handler, pattern, root string) {
	if r.Method != "CONNECT" {
		if p := cleanPath(r.URL.Path); p != r.URL.Path {
			_, pattern = mux.handler(r.Host, p)
			url := *r.URL
			url.Path = p
			return http.RedirectHandler(url.String(), http.StatusMovedPermanently), pattern, root
		}
	}

	h, pattern = mux.handler(r.Host, r.URL.Path)
	// If parent has a non-root matching pattern, then it
	// should take priority over child pattern (and it's root)
	if mux.childMux != nil {
		if pattern == "/" || pattern == "" {
			root, cPath := splitRootAndPath(r.URL.Path)
			if root != "" {
				h, pattern = mux.childMux.handler(r.Host, cPath)
				pattern = "/" + root + pattern
			}
		}
	}

	return h, pattern, root
}

// handler is the main implementation of Handler.
// The path is known to be in canonical form, except for CONNECT methods.
func (mux *Mux) handler(host, path string) (h http.Handler, pattern string) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	// Host-specific pattern takes precedence over generic ones
	if mux.hosts {
		h, pattern = mux.match(host + path)
	}
	if h == nil {
		h, pattern = mux.match(path)
	}

	if h == nil {
		h, pattern = http.NotFoundHandler(), ""
	}
	return
}

// ServeHTTP dispatches the request to the handler whose
// pattern most closely matches the request URL.
func (mux *Mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.RequestURI == "*" {
		if r.ProtoAtLeast(1, 1) {
			w.Header().Set("Connection", "close")
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	h, _, _ := mux.Handler(r)
	h.ServeHTTP(w, r)
}

// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
func (mux *Mux) Handle(pattern string, handler http.Handler) {
	mux.mu.Lock()
	defer mux.mu.Unlock()

	if pattern == "" {
		panic("treemux: invalid pattern " + pattern)
	}
	if handler == nil {
		panic("treemux: nil handler")
	}
	if mux.m[pattern].explicit {
		panic("treemux: multiple registrations for " + pattern)
	}

	mux.m[pattern] = muxEntry{explicit: true, h: handler, pattern: pattern}

	if pattern[0] != '/' {
		mux.hosts = true
	}

	// Helpful behavior:
	// If pattern is /tree/, insert an implicit permanent redirect for /tree.
	// It can be overridden by an explicit registration.
	n := len(pattern)
	if n > 0 && pattern[n-1] == '/' && !mux.m[pattern[0:n-1]].explicit {
		// If pattern contains a host name, strip it and use remaining
		// path for redirect.
		path := pattern
		if pattern[0] != '/' {
			// In pattern, at least the last character is a '/', so
			// strings.Index can't be -1.
			path = pattern[strings.Index(pattern, "/"):]
		}

		if mux.IsChild() {
			// ChildMux doesn't know what it's redirect should be at Handle registration time
			// so it needs to be looked up and parsed from the current URL
			mux.m[pattern[0:n-1]] = muxEntry{
				h:       childRedirectHandlerFunc(path, http.StatusMovedPermanently, mux.depth),
				pattern: pattern,
			}
		} else {
			mux.m[pattern[0:n-1]] = muxEntry{
				h:       http.RedirectHandler(path, http.StatusMovedPermanently),
				pattern: pattern,
			}
		}
	}
}

// HandleFunc registers the handler function for the given pattern.
func (mux *Mux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	mux.Handle(pattern, http.HandlerFunc(handler))
}

type childRedirectHandler struct {
	url   string
	code  int
	depth int
}

func (ch *childRedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/"+root(r, ch.depth)+ch.url, ch.code)
}

// RedirectHandler returns a request handler that redirects
// each request it receives to the given url using the given
// status code.
func childRedirectHandlerFunc(url string, code, depth int) http.Handler {
	return &childRedirectHandler{url, code, depth}
}
