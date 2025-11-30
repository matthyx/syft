package internal

import (
	"bytes"
	"io"
	"regexp"
	"regexp/syntax"
	"sync"
)

// readerChunkSize is the size of chunks read when scanning binary files for version strings.
// 256KB is sufficient for most version patterns while reducing memory usage and allowing
// faster early termination compared to the previous 1MB chunk size.
const readerChunkSize = 256 * 1024

// maxBinaryReadSize limits how much of a binary file we read when searching for version strings.
// Most version information appears in the first few MB of a binary. Reading beyond this
// is unlikely to find matches and wastes CPU/IO. Set to 0 to disable the limit.
const maxBinaryReadSize = 4 * 1024 * 1024 // 4MB

// bufferPool is a sync.Pool for reusing buffers in processReaderInChunks
// to reduce GC pressure from repeated allocations.
var bufferPool = sync.Pool{
	New: func() interface{} {
		// allocate buffer size = chunkSize + half = 1.5 * chunkSize
		buf := make([]byte, readerChunkSize+readerChunkSize/2)
		return &buf
	},
}

// countingReader wraps a reader and counts bytes read
type countingReader struct {
	r         io.Reader
	bytesRead int64
	limit     int64
}

func (c *countingReader) Read(p []byte) (n int, err error) {
	if c.limit > 0 && c.bytesRead >= c.limit {
		return 0, io.EOF
	}
	n, err = c.r.Read(p)
	c.bytesRead += int64(n)
	return n, err
}

// extractLiteralPrefix attempts to extract a literal string prefix from a regex pattern.
// This can be used for fast pre-filtering with bytes.Contains before running the full regex.
// Returns nil if no useful literal prefix can be extracted.
func extractLiteralPrefix(re *regexp.Regexp) []byte {
	// Parse the regex to extract literal prefix
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}

	return extractLiteralFromSyntax(parsed)
}

// extractLiteralFromSyntax recursively extracts literal bytes from a parsed regex
func extractLiteralFromSyntax(re *syntax.Regexp) []byte {
	switch re.Op {
	case syntax.OpLiteral:
		// Direct literal - convert runes to bytes
		result := make([]byte, 0, len(re.Rune))
		for _, r := range re.Rune {
			if r < 128 { // Only ASCII for simplicity
				result = append(result, byte(r))
			} else {
				break
			}
		}
		if len(result) >= 3 { // Only return if prefix is meaningful (3+ chars)
			return result
		}
		return nil

	case syntax.OpConcat:
		// Concatenation - try to get literal from the beginning
		var result []byte
		for _, sub := range re.Sub {
			literal := extractLiteralFromSyntax(sub)
			if literal != nil {
				result = append(result, literal...)
			} else {
				break // Stop at first non-literal
			}
		}
		if len(result) >= 3 {
			return result
		}
		return nil

	case syntax.OpCapture:
		// Look inside capture groups
		if len(re.Sub) > 0 {
			return extractLiteralFromSyntax(re.Sub[0])
		}
		return nil

	case syntax.OpQuest, syntax.OpStar, syntax.OpPlus:
		// Optional/repeated - can't use as required prefix
		return nil

	default:
		return nil
	}
}

// MatchNamedCaptureGroups takes a regular expression and string and returns all of the named capture group results in a map.
// This is only for the first match in the regex. Callers shouldn't be providing regexes with multiple capture groups with the same name.
func MatchNamedCaptureGroups(regEx *regexp.Regexp, content string) map[string]string {
	// note: we are looking across all matches and stopping on the first non-empty match. Why? Take the following example:
	// input: "cool something to match against" pattern: `((?P<name>match) (?P<version>against))?`. Since the pattern is
	// encapsulated in an optional capture group, there will be results for each character, but the results will match
	// on nothing. The only "true" match will be at the end ("match against").
	allMatches := regEx.FindAllStringSubmatch(content, -1)
	var results map[string]string
	for _, match := range allMatches {
		// fill a candidate results map with named capture group results, accepting empty values, but not groups with
		// no names
		for nameIdx, name := range regEx.SubexpNames() {
			if nameIdx > len(match) || len(name) == 0 {
				continue
			}
			if results == nil {
				results = make(map[string]string)
			}
			results[name] = match[nameIdx]
		}
		// note: since we are looking for the first best potential match we should stop when we find the first one
		// with non-empty results.
		if !isEmptyMap(results) {
			break
		}
	}
	return results
}

// MatchNamedCaptureGroupsFromReader matches named capture groups from a reader, assuming the pattern fits within
// 1.5x the reader chunk size (384KB with default 256KB chunks).
// To avoid scanning extremely large files, reading stops after maxBinaryReadSize bytes.
func MatchNamedCaptureGroupsFromReader(re *regexp.Regexp, r io.Reader) (map[string]string, error) {
	results := make(map[string]string)
	// Wrap with counting reader to limit how much we read from large binaries
	cr := &countingReader{r: r, limit: maxBinaryReadSize}
	matches, err := processReaderInChunks(cr, readerChunkSize, matchNamedCaptureGroupsHandler(re, results))
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, nil
	}
	return results, nil
}

// MatchNamedCaptureGroupsFromLimitedReader matches named capture groups from a reader, but only reads up to maxBytes.
// This is useful for binary version detection where version strings typically appear near the beginning of files.
// If maxBytes is 0 or negative, it behaves like MatchNamedCaptureGroupsFromReader (no limit).
func MatchNamedCaptureGroupsFromLimitedReader(re *regexp.Regexp, r io.Reader, maxBytes int64) (map[string]string, error) {
	if maxBytes <= 0 {
		return MatchNamedCaptureGroupsFromReader(re, r)
	}
	limitedReader := io.LimitReader(r, maxBytes)
	return MatchNamedCaptureGroupsFromReader(re, limitedReader)
}

// MatchAnyFromReader matches any of the provided regular expressions from a reader, assuming the pattern fits within
// 1.5x the reader chunk size (384KB with default 256KB chunks).
// To avoid scanning extremely large files, reading stops after maxBinaryReadSize bytes.
func MatchAnyFromReader(r io.Reader, res ...*regexp.Regexp) (bool, error) {
	// Wrap with counting reader to limit how much we read from large binaries
	cr := &countingReader{r: r, limit: maxBinaryReadSize}
	return processReaderInChunks(cr, readerChunkSize, matchAnyHandler(res))
}

func matchNamedCaptureGroupsHandler(re *regexp.Regexp, results map[string]string) func(data []byte) (bool, error) {
	// Pre-extract literal prefix for fast filtering
	literalPrefix := extractLiteralPrefix(re)

	return func(data []byte) (bool, error) {
		// Fast path: if we have a literal prefix, check if it exists before running regex
		if literalPrefix != nil && !bytes.Contains(data, literalPrefix) {
			return false, nil
		}

		if match := re.FindSubmatch(data); match != nil {
			groupNames := re.SubexpNames()
			for i, name := range groupNames {
				if i > 0 && name != "" {
					results[name] = string(match[i])
				}
			}
			return true, nil
		}
		return false, nil
	}
}

func matchAnyHandler(res []*regexp.Regexp) func(data []byte) (bool, error) {
	// Pre-extract literal prefixes for all regexes
	prefixes := make([][]byte, len(res))
	for i, re := range res {
		prefixes[i] = extractLiteralPrefix(re)
	}

	return func(data []byte) (bool, error) {
		for i, re := range res {
			// Fast path: if we have a literal prefix, check if it exists before running regex
			if prefixes[i] != nil && !bytes.Contains(data, prefixes[i]) {
				continue
			}
			if re.Match(data) {
				return true, nil
			}
		}
		return false, nil
	}
}

// processReaderInChunks reads from the provided reader in chunks and calls the provided handler with each chunk + portion of the previous neighboring chunk.
// Note that we only overlap the last half of the previous chunk with the current chunk to avoid missing matches that span chunk boundaries.
func processReaderInChunks(rdr io.Reader, chunkSize int, handler func(data []byte) (bool, error)) (bool, error) {
	half := chunkSize / 2
	bufSize := chunkSize + half

	// Get buffer from pool or allocate if needed for non-standard chunk sizes
	var buf []byte
	if chunkSize == readerChunkSize {
		bufPtr := bufferPool.Get().(*[]byte)
		buf = *bufPtr
		defer bufferPool.Put(bufPtr)
	} else {
		buf = make([]byte, bufSize)
	}

	lastRead := 0

	for {
		offset := half
		if lastRead < half {
			offset = lastRead
		}
		start := half - offset
		if lastRead > 0 {
			copy(buf[start:], buf[half+offset:half+lastRead])
		}
		n, err := rdr.Read(buf[half:])
		if err != nil {
			break
		}

		// process the combined data with the handler
		matched, handlerErr := handler(buf[start : half+n])
		if handlerErr != nil {
			return false, handlerErr
		}
		if matched {
			return true, nil
		}

		lastRead = n
	}

	return false, nil
}

func isEmptyMap(m map[string]string) bool {
	if len(m) == 0 {
		return true
	}
	for _, value := range m {
		if value != "" {
			return false
		}
	}
	return true
}
