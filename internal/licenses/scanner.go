package licenses

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/google/licensecheck"

	"github.com/anchore/syft/internal/log"
)

const (
	UnknownLicensePrefix     = unknownLicenseType + "_"
	DefaultCoverageThreshold = 75 // determined by experimentation

	unknownLicenseType = "UNKNOWN"

	// MaxLicenseScanSize is the maximum number of bytes to read when scanning for license text.
	// License text is almost always found in file headers, so we truncate input to reduce
	// memory usage and CPU time for large files. 16KB is generous enough to capture
	// all common license texts while significantly improving performance.
	MaxLicenseScanSize = 16 * 1024 // 16KB
)

type Evidence struct {
	ID    string            // License identifier. (See licenses/README.md.)
	Type  licensecheck.Type // The type of the license: BSD, MIT, etc.
	Start int               // Start offset of match in text; match is at text[Start:End].
	End   int               // End offset of match in text.
	IsURL bool              // Whether match is a URL.
}

type Scanner interface {
	FindEvidence(context.Context, io.Reader) ([]Evidence, []byte, error)
}

var _ Scanner = (*scanner)(nil)

type scanner struct {
	coverageThreshold float64 // between 0 and 100
	scanner           func([]byte) licensecheck.Coverage
}

type ScannerConfig struct {
	CoverageThreshold float64
	Scanner           func([]byte) licensecheck.Coverage
}

type Option func(*scanner)

func WithCoverage(coverage float64) Option {
	return func(s *scanner) {
		s.coverageThreshold = coverage
	}
}

// defaultScannerOnce ensures that the expensive licensecheck.NewScanner is only called once.
// The DFA/NFA compilation for license patterns is very expensive (~400MB allocations),
// so we use a singleton pattern to share the compiled scanner across all uses.
var (
	defaultScannerOnce     sync.Once
	defaultScannerInstance *licensecheck.Scanner
	defaultScannerErr      error
)

// getDefaultLicenseCheckScanner returns the singleton licensecheck.Scanner instance.
// This ensures the expensive DFA/NFA compilation only happens once per process.
func getDefaultLicenseCheckScanner() (*licensecheck.Scanner, error) {
	defaultScannerOnce.Do(func() {
		defaultScannerInstance, defaultScannerErr = licensecheck.NewScanner(licensecheck.BuiltinLicenses())
		if defaultScannerErr != nil {
			log.WithFields("error", defaultScannerErr).Trace("unable to create default license scanner")
		}
	})
	return defaultScannerInstance, defaultScannerErr
}

// NewDefaultScanner returns a scanner that uses the singleton default licensecheck package scanner.
// The underlying licensecheck.Scanner is compiled only once and shared across all callers,
// significantly reducing memory usage when multiple scanners are created.
func NewDefaultScanner(o ...Option) (Scanner, error) {
	s, err := getDefaultLicenseCheckScanner()
	if err != nil {
		return nil, fmt.Errorf("unable to create default license scanner: %w", err)
	}

	newScanner := &scanner{
		coverageThreshold: DefaultCoverageThreshold,
		scanner:           s.Scan,
	}

	for _, opt := range o {
		opt(newScanner)
	}
	return newScanner, nil
}

// NewScanner generates a license Scanner with the given ScannerConfig
// if config is nil NewDefaultScanner is used
func NewScanner(c *ScannerConfig) (Scanner, error) {
	if c == nil {
		return NewDefaultScanner()
	}

	return &scanner{
		coverageThreshold: c.CoverageThreshold,
		scanner:           c.Scanner,
	}, nil
}
