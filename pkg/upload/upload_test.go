package upload_test

import (
	"bytes"
	"mime/multipart"
	"testing"

	"github.com/spectrum-labs-tech/go-toolkit/pkg/upload"
)

// pdfMagic is the minimal byte sequence that makes mimetype detect application/pdf.
var pdfMagic = []byte("%PDF-1.4\n")

// pngMagic is the PNG file signature.
var pngMagic = []byte("\x89PNG\r\n\x1a\n")

func makeHeader(t *testing.T, filename string, content []byte) *multipart.FileHeader {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	w.Close()

	mr := multipart.NewReader(&buf, w.Boundary())
	form, err := mr.ReadForm(10 << 20)
	if err != nil {
		t.Fatalf("ReadForm: %v", err)
	}
	files := form.File["file"]
	if len(files) == 0 {
		t.Fatal("no file in parsed form")
	}
	return files[0]
}

func TestValidate_NoOptions(t *testing.T) {
	t.Parallel()
	header := makeHeader(t, "any.bin", []byte("whatever content"))
	if err := upload.Validate(header); err != nil {
		t.Errorf("no options: unexpected error: %v", err)
	}
}

func TestValidate_WithinSizeLimit(t *testing.T) {
	t.Parallel()
	header := makeHeader(t, "small.pdf", pdfMagic)
	if err := upload.Validate(header, upload.MaxBytes(1024)); err != nil {
		t.Errorf("within limit: unexpected error: %v", err)
	}
}

func TestValidate_ExceedsSizeLimit(t *testing.T) {
	t.Parallel()
	content := make([]byte, 100)
	header := makeHeader(t, "big.pdf", content)
	err := upload.Validate(header, upload.MaxBytes(10))
	if err == nil {
		t.Error("expected error for oversized file, got nil")
	}
}

func TestValidate_AllowedMIME_Pass(t *testing.T) {
	t.Parallel()
	header := makeHeader(t, "doc.pdf", pdfMagic)
	if err := upload.Validate(header, upload.AllowMIME("application/pdf")); err != nil {
		t.Errorf("valid PDF: unexpected error: %v", err)
	}
}

func TestValidate_AllowedMIME_Blocked(t *testing.T) {
	t.Parallel()
	// PNG content presented with a .pdf extension — should be rejected.
	header := makeHeader(t, "sneaky.pdf", pngMagic)
	err := upload.Validate(header, upload.AllowMIME("application/pdf"))
	if err == nil {
		t.Error("expected error for PNG disguised as PDF, got nil")
	}
}

func TestValidate_MultipleAllowedMIMEs(t *testing.T) {
	t.Parallel()
	pdfHeader := makeHeader(t, "a.pdf", pdfMagic)
	pngHeader := makeHeader(t, "b.png", pngMagic)

	opts := []upload.Option{upload.AllowMIME("application/pdf", "image/png")}

	if err := upload.Validate(pdfHeader, opts...); err != nil {
		t.Errorf("PDF in multi-allow list: unexpected error: %v", err)
	}
	if err := upload.Validate(pngHeader, opts...); err != nil {
		t.Errorf("PNG in multi-allow list: unexpected error: %v", err)
	}
}

func TestValidate_SizeAndMIMECombined(t *testing.T) {
	t.Parallel()
	// Size check runs before MIME detection — oversized file rejected first.
	header := makeHeader(t, "big.pdf", pdfMagic)
	err := upload.Validate(header,
		upload.MaxBytes(1),
		upload.AllowMIME("application/pdf"),
	)
	if err == nil {
		t.Error("expected size error, got nil")
	}
}
