// Package upload provides validation helpers for multipart file uploads.
// It combines file size enforcement with actual MIME type detection — sniffing
// the file's own bytes rather than trusting the browser-supplied Content-Type
// header, which can be trivially spoofed.
//
// # Basic usage
//
//	err := upload.Validate(header,
//	    upload.MaxBytes(50<<20),                  // 50 MB
//	    upload.AllowMIME("application/pdf"),
//	)
//	if err != nil {
//	    c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
//	    return
//	}
//
// # MIME detection
//
// AllowMIME uses [github.com/gabriel-vasile/mimetype] to detect the file type
// from its leading bytes. Only as many bytes as needed for detection are read
// (typically 512 or fewer); the full file is not buffered.
package upload

import (
	"fmt"
	"mime/multipart"

	"github.com/gabriel-vasile/mimetype"
)

// Option configures a Validate call.
type Option func(*validator)

type validator struct {
	maxBytes     int64
	allowedMIMEs []string
}

// MaxBytes sets the maximum permitted file size in bytes. Files larger than n
// are rejected before the file is opened. No size limit is enforced when
// MaxBytes is not provided.
func MaxBytes(n int64) Option {
	return func(v *validator) { v.maxBytes = n }
}

// AllowMIME restricts uploads to the listed MIME types. The actual file bytes
// are sniffed to determine the type — the Content-Type value supplied by the
// browser in the multipart form is not used. Pass full type/subtype strings
// such as "application/pdf" or "image/jpeg".
//
// When AllowMIME is not provided, any MIME type is accepted.
func AllowMIME(types ...string) Option {
	return func(v *validator) { v.allowedMIMEs = append(v.allowedMIMEs, types...) }
}

// Validate checks header against the provided options and returns a descriptive
// error if any constraint is violated:
//
//   - MaxBytes: checked against header.Size before the file is opened.
//   - AllowMIME: file is opened and its leading bytes are sniffed. The check
//     uses MIME alias awareness so that, for example, "application/x-pdf" and
//     "application/pdf" both match when "application/pdf" is allowed.
//
// Returns nil when all constraints pass.
func Validate(header *multipart.FileHeader, opts ...Option) error {
	v := &validator{}
	for _, o := range opts {
		o(v)
	}

	if v.maxBytes > 0 && header.Size > v.maxBytes {
		return fmt.Errorf("file size %d bytes exceeds maximum of %d bytes", header.Size, v.maxBytes)
	}

	if len(v.allowedMIMEs) == 0 {
		return nil
	}

	f, err := header.Open()
	if err != nil {
		return fmt.Errorf("open file for MIME detection: %w", err)
	}
	defer f.Close()

	detected, err := mimetype.DetectReader(f)
	if err != nil {
		return fmt.Errorf("detect MIME type: %w", err)
	}

	for _, allowed := range v.allowedMIMEs {
		if detected.Is(allowed) {
			return nil
		}
	}

	return fmt.Errorf("file type %q is not allowed", detected.String())
}
