package ginmiddleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/ginmiddleware"
)

func requestSizeRouter(maxBytes int64) *gin.Engine {
	r := gin.New()
	r.Use(ginmiddleware.RequestSizeLimit(maxBytes))
	r.POST("/", func(c *gin.Context) {
		// Drain the body so MaxBytesReader can trip.
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			return
		}
		c.Status(http.StatusOK)
	})
	return r
}

func TestRequestSizeLimit_WithinLimit(t *testing.T) {
	t.Parallel()
	r := requestSizeRouter(100)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("small body"))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequestSizeLimit_ContentLengthExceeds(t *testing.T) {
	t.Parallel()
	r := requestSizeRouter(10)

	// Client declares a large Content-Length — rejected before body is read.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x"))
	req.ContentLength = 9999
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 on oversized Content-Length, got %d", w.Code)
	}
}

func TestRequestSizeLimit_BodyExceeds_NoContentLength(t *testing.T) {
	t.Parallel()
	r := requestSizeRouter(5)

	// No Content-Length declared — MaxBytesReader catches the overrun during read.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("this body is too long"))
	req.ContentLength = -1
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413 on oversized body without Content-Length, got %d", w.Code)
	}
}

func TestRequestSizeLimit_ZeroDisabled(t *testing.T) {
	t.Parallel()
	// maxBytes=0 disables the limit — any body passes through.
	r := requestSizeRouter(0)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("some content"))
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with limit disabled, got %d", w.Code)
	}
}
