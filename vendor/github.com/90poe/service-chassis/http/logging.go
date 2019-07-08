package http

import (
	"net/http"
	"time"

	"github.com/90poe/service-chassis/logging"
	"github.com/davecgh/go-spew/spew"
)

func LoggingMiddleware(next http.Handler, logEntryFactory logging.LogEntryFactory) http.Handler {

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {

		start := time.Now()

		defer func() {
			if r := recover(); r != nil {
				if logging.GetLogLevel() == logging.DEBUG {
					// Debug contains request
					logging.DebugHTTPMethodPanic(logEntryFactory)(req.Context()).
						WithField("request", spew.Sdump(req)).
						WithField("method", req.Method).
						WithField("uri", req.URL.RequestURI()).
						WithField("contentLength", req.ContentLength).
						WithField("remoteAddr", req.RemoteAddr).
						WithField("userAgent", req.UserAgent()).
						WithField("duration", time.Since(start).String()).
						Write(r)
				} else {
					logging.HTTPMethodPanic(logEntryFactory)(req.Context()).
						WithField("method", req.Method).
						WithField("uri", req.URL.RequestURI()).
						WithField("contentLength", req.ContentLength).
						WithField("remoteAddr", req.RemoteAddr).
						WithField("userAgent", req.UserAgent()).
						WithField("duration", time.Since(start).String()).
						Write(r)
				}

				panic(r)
			}
		}()

		logging.DebugHTTPMethodEntry(logEntryFactory)(req.Context()).
			WithField("method", req.Method).
			WithField("uri", req.URL.RequestURI()).
			WithField("contentLength", req.ContentLength).
			WithField("remoteAddr", req.RemoteAddr).
			WithField("userAgent", req.UserAgent()).
			Write("method called")

		next.ServeHTTP(rw, req)

		logging.DebugHTTPMethodExit(logEntryFactory)(req.Context()).
			WithField("method", req.Method).
			WithField("uri", req.URL.RequestURI()).
			WithField("contentLength", req.ContentLength).
			WithField("remoteAddr", req.RemoteAddr).
			WithField("userAgent", req.UserAgent()).
			WithField("duration", time.Since(start).String()).
			Write("method responded")
	})
}
