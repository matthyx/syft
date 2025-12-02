package internal

import (
	"bytes"
	"io"
	"regexp"
	"regexp/syntax"
	"sync"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
)

// readerChunkSize is the size of chunks read when scanning binary files for version strings.
// 1MB chunks work well with Aho-Corasick since the algorithm is very efficient at scanning.
const readerChunkSize = 1024 * 1024

// matchWindowSize is the size of the window around a literal match to extract for regex matching.
// This should be large enough to capture the full version pattern around any literal match.
const matchWindowSize = 4096

// overlapSize is the overlap between chunks to handle matches that span chunk boundaries.
const overlapSize = matchWindowSize

// bufferPool is a sync.Pool for reusing buffers in processReaderInChunks
// to reduce GC pressure from repeated allocations.
var bufferPool = sync.Pool{
	New: func() interface{} {
		// allocate buffer size = chunkSize + overlap
		buf := make([]byte, readerChunkSize+overlapSize)
		return &buf
	},
}

// extractLiteralPrefix attempts to extract a literal string prefix from a regex pattern.
// This can be used for fast pre-filtering before running the full regex.
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

// extractAllLiterals extracts all meaningful literal sequences from a regex pattern.
// Unlike extractLiteralPrefix, this finds literals anywhere in the pattern.
// It only extracts REQUIRED literals - literals inside optional groups (?, *, alternations)
// are not included since they may not appear in every match.
func extractAllLiterals(re *regexp.Regexp) [][]byte {
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return nil
	}

	var literals [][]byte
	extractLiteralsRecursive(parsed, &literals, true)
	return literals
}

// extractLiteralsRecursive extracts literals from a parsed regex.
// The 'required' parameter indicates whether literals found here are required for a match.
// Literals inside optional groups (?, *, alternations) are not required.
func extractLiteralsRecursive(re *syntax.Regexp, literals *[][]byte, required bool) {
	switch re.Op {
	case syntax.OpLiteral:
		if !required {
			return // Skip optional literals
		}
		result := make([]byte, 0, len(re.Rune))
		for _, r := range re.Rune {
			if r < 128 {
				result = append(result, byte(r))
			} else {
				break
			}
		}
		if len(result) >= 3 {
			*literals = append(*literals, result)
		}

	case syntax.OpConcat:
		// For concatenation, try to build longer literals by combining adjacent OpLiteral nodes
		var currentLiteral []byte
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral && required {
				for _, r := range sub.Rune {
					if r < 128 {
						currentLiteral = append(currentLiteral, byte(r))
					} else {
						break
					}
				}
			} else {
				// Save current literal if long enough
				if len(currentLiteral) >= 3 {
					*literals = append(*literals, currentLiteral)
				}
				currentLiteral = nil
				// Recurse into non-literal parts
				extractLiteralsRecursive(sub, literals, required)
			}
		}
		// Don't forget trailing literal
		if len(currentLiteral) >= 3 {
			*literals = append(*literals, currentLiteral)
		}

	case syntax.OpCapture:
		// Capture groups don't affect whether content is required
		for _, sub := range re.Sub {
			extractLiteralsRecursive(sub, literals, required)
		}

	case syntax.OpAlternate:
		// Alternations: literals inside are not guaranteed to appear
		// (only one branch will match), so mark as not required
		for _, sub := range re.Sub {
			extractLiteralsRecursive(sub, literals, false)
		}

	case syntax.OpQuest:
		// Optional (?) - content is not required
		for _, sub := range re.Sub {
			extractLiteralsRecursive(sub, literals, false)
		}

	case syntax.OpStar, syntax.OpPlus:
		// * means 0 or more (not required), + means 1 or more (required)
		// But even with +, the content could be variable, so be conservative
		for _, sub := range re.Sub {
			extractLiteralsRecursive(sub, literals, false)
		}
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

// MatchNamedCaptureGroupsFromReader matches named capture groups from a reader using Aho-Corasick
// string search for efficient scanning of large files. This approach has no size limit and can
// efficiently scan arbitrarily large binaries by first finding literal patterns with Aho-Corasick,
// then applying regex only on small windows around matches.
func MatchNamedCaptureGroupsFromReader(re *regexp.Regexp, r io.Reader) (map[string]string, error) {
	// Extract literals from the regex for fast searching
	literals := extractAllLiterals(re)

	// If we found usable literals, use Aho-Corasick search
	if len(literals) > 0 {
		return matchWithAhoCorasick(re, r, literals)
	}

	// Fallback to chunk-based regex processing if no literals found
	results := make(map[string]string)
	matches, err := processReaderInChunks(r, readerChunkSize, matchNamedCaptureGroupsHandler(re, results))
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, nil
	}
	return results, nil
}

// matchWithAhoCorasick uses Aho-Corasick to find literal patterns then applies regex
func matchWithAhoCorasick(re *regexp.Regexp, r io.Reader, literals [][]byte) (map[string]string, error) {
	// Build Aho-Corasick trie from literals
	builder := ahocorasick.NewTrieBuilder()
	for _, lit := range literals {
		builder.AddPattern(lit)
	}
	trie := builder.Build()

	// Get buffer from pool
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	carryOver := 0

	for {
		// Read into buffer after any carried over data
		n, err := io.ReadFull(r, buf[carryOver:readerChunkSize+carryOver])
		if n == 0 && err != nil {
			break
		}

		dataLen := carryOver + n
		data := buf[:dataLen]

		// Search for all literals using Aho-Corasick (single pass!)
		matches := trie.Match(data)

		for _, match := range matches {
			idx := int(match.Pos())

			// Extract window around match for regex processing
			windowStart := idx - matchWindowSize/2
			if windowStart < 0 {
				windowStart = 0
			}
			windowEnd := idx + len(match.Match()) + matchWindowSize/2
			if windowEnd > dataLen {
				windowEnd = dataLen
			}

			window := data[windowStart:windowEnd]

			// Apply regex to the window
			if regexMatch := re.FindSubmatch(window); regexMatch != nil {
				results := make(map[string]string)
				groupNames := re.SubexpNames()
				for i, name := range groupNames {
					if i > 0 && name != "" && i < len(regexMatch) {
						results[name] = string(regexMatch[i])
					}
				}
				if !isEmptyMap(results) {
					return results, nil
				}
			}
		}

		// If we got EOF or short read, we're done
		if err != nil {
			break
		}

		// Keep overlap for next iteration to handle boundary matches
		if dataLen > overlapSize {
			copy(buf[:overlapSize], buf[dataLen-overlapSize:dataLen])
			carryOver = overlapSize
		} else {
			carryOver = dataLen
		}
	}

	return nil, nil
}

// MatchAnyFromReader matches any of the provided regular expressions from a reader using
// Aho-Corasick string search for efficient scanning of large files. This approach has no
// size limit and can efficiently scan arbitrarily large binaries.
func MatchAnyFromReader(r io.Reader, res ...*regexp.Regexp) (bool, error) {
	// Collect all literals from all regexes
	var allLiterals [][]byte
	literalToRegexes := make(map[string][]*regexp.Regexp)
	regexesWithLiterals := make(map[*regexp.Regexp]bool)

	for _, re := range res {
		literals := extractAllLiterals(re)
		for _, lit := range literals {
			key := string(lit)
			if _, exists := literalToRegexes[key]; !exists {
				allLiterals = append(allLiterals, lit)
			}
			literalToRegexes[key] = append(literalToRegexes[key], re)
			regexesWithLiterals[re] = true
		}
	}

	// Identify regexes without literals (need fallback)
	var regexesWithoutLiterals []*regexp.Regexp
	for _, re := range res {
		if !regexesWithLiterals[re] {
			regexesWithoutLiterals = append(regexesWithoutLiterals, re)
		}
	}

	// If we found usable literals, use Aho-Corasick search
	if len(allLiterals) > 0 {
		found, err := matchAnyWithAhoCorasick(r, allLiterals, literalToRegexes, regexesWithoutLiterals)
		if err != nil || found {
			return found, err
		}
	}

	// If no literals found at all, fallback to chunk-based processing
	if len(allLiterals) == 0 {
		return processReaderInChunks(r, readerChunkSize, matchAnyHandler(res))
	}

	return false, nil
}

// matchAnyWithAhoCorasick uses Aho-Corasick to find literal patterns then applies regex
func matchAnyWithAhoCorasick(r io.Reader, literals [][]byte, literalToRegexes map[string][]*regexp.Regexp, fallbackRegexes []*regexp.Regexp) (bool, error) {
	// Build Aho-Corasick trie from all literals
	builder := ahocorasick.NewTrieBuilder()
	for _, lit := range literals {
		builder.AddPattern(lit)
	}
	trie := builder.Build()

	// Get buffer from pool
	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	carryOver := 0

	for {
		n, err := io.ReadFull(r, buf[carryOver:readerChunkSize+carryOver])
		if n == 0 && err != nil {
			break
		}

		dataLen := carryOver + n
		data := buf[:dataLen]

		// Search for all literals using Aho-Corasick (single pass!)
		matches := trie.Match(data)

		for _, match := range matches {
			idx := int(match.Pos())

			// Extract window around match
			windowStart := idx - matchWindowSize/2
			if windowStart < 0 {
				windowStart = 0
			}
			windowEnd := idx + len(match.Match()) + matchWindowSize/2
			if windowEnd > dataLen {
				windowEnd = dataLen
			}

			window := data[windowStart:windowEnd]

			// Try matching regexes associated with this literal
			for _, re := range literalToRegexes[string(match.Match())] {
				if re.Match(window) {
					return true, nil
				}
			}
		}

		// Also try fallback regexes (those without literals) on each chunk
		for _, re := range fallbackRegexes {
			if re.Match(data) {
				return true, nil
			}
		}

		if err != nil {
			break
		}

		if dataLen > overlapSize {
			copy(buf[:overlapSize], buf[dataLen-overlapSize:dataLen])
			carryOver = overlapSize
		} else {
			carryOver = dataLen
		}
	}

	return false, nil
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
// Note that we overlap chunks to avoid missing matches that span chunk boundaries.
func processReaderInChunks(rdr io.Reader, chunkSize int, handler func(data []byte) (bool, error)) (bool, error) {
	bufSize := chunkSize + overlapSize

	// Get buffer from pool or allocate if needed for non-standard chunk sizes
	var buf []byte
	if chunkSize == readerChunkSize {
		bufPtr := bufferPool.Get().(*[]byte)
		buf = *bufPtr
		defer bufferPool.Put(bufPtr)
	} else {
		buf = make([]byte, bufSize)
	}

	carryOver := 0

	for {
		n, err := rdr.Read(buf[carryOver : chunkSize+carryOver])
		if n == 0 && err != nil {
			break
		}

		dataLen := carryOver + n

		// process the data with the handler
		matched, handlerErr := handler(buf[:dataLen])
		if handlerErr != nil {
			return false, handlerErr
		}
		if matched {
			return true, nil
		}

		if err != nil {
			break
		}

		// Keep overlap for next iteration
		overlap := overlapSize
		if overlap > chunkSize/2 {
			overlap = chunkSize / 2
		}
		if dataLen > overlap {
			copy(buf[:overlap], buf[dataLen-overlap:dataLen])
			carryOver = overlap
		} else {
			carryOver = dataLen
		}
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
