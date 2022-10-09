package filters

import (
	"net/http"
	"path"
)

func WithAllowPaths(handler http.Handler, allowPaths []string) http.Handler {
	if len(allowPaths) == 0 {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for _, pathAllowed := range allowPaths {
			found, err := path.Match(pathAllowed, req.URL.Path)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}

			if found {
				handler.ServeHTTP(w, req)
				return
			}
		}

		http.NotFound(w, req)
	})
}

func WithIgnorePaths(ignored http.Handler, handler http.Handler, ignorePaths []string) http.Handler {
	if len(ignorePaths) == 0 {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for _, pathIgnored := range ignorePaths {
			ignorePathFound, err := path.Match(pathIgnored, req.URL.Path)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}

			if ignorePathFound {
				ignored.ServeHTTP(w, req)
				return
			}
		}

		handler.ServeHTTP(w, req)
	})
}
