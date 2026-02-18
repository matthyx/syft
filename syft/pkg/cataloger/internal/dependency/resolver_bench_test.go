package dependency

import (
	"fmt"
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func BenchmarkDeduplicate(b *testing.B) {
	input := generateDuplicateStrings(100, 50)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deduplicate(input)
	}
}

func BenchmarkDeduplicate_Large(b *testing.B) {
	input := generateDuplicateStrings(1000, 200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deduplicate(input)
	}
}

func BenchmarkDeduplicate_VeryLarge(b *testing.B) {
	input := generateDuplicateStrings(5000, 500)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deduplicate(input)
	}
}

func BenchmarkDeduplicate_Memory(b *testing.B) {
	input := generateDuplicateStrings(5000, 500)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deduplicate(input)
	}
}

func BenchmarkResolve_CraftedRelationships(b *testing.B) {
	pkgs := generatePackages(100, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Resolve(testDependencySpecifier, pkgs)
	}
}

func BenchmarkResolve_CraftedRelationships_Large(b *testing.B) {
	pkgs := generatePackages(500, 200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Resolve(testDependencySpecifier, pkgs)
	}
}

func BenchmarkResolve_CraftedRelationships_VeryLarge(b *testing.B) {
	pkgs := generatePackages(1000, 500)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Resolve(testDependencySpecifier, pkgs)
	}
}

func generateDuplicateStrings(total, unique int) []string {
	result := make([]string, total)
	for i := 0; i < total; i++ {
		result[i] = fmt.Sprintf("resource-%d", i%unique)
	}
	return result
}

func generatePackages(numPkgs, numResources int) []pkg.Package {
	pkgs := make([]pkg.Package, numPkgs)
	for i := 0; i < numPkgs; i++ {
		p := pkg.Package{
			Name:     fmt.Sprintf("package-%d", i),
			Version:  fmt.Sprintf("1.0.%d", i),
			Language: pkg.JavaScript,
		}
		p.SetID()
		pkgs[i] = p
	}
	return pkgs
}

func testDependencySpecifier(p pkg.Package) Specification {
	return Specification{
		ProvidesRequires: ProvidesRequires{
			Provides: []string{
				fmt.Sprintf("provides-%s", p.Name),
			},
			Requires: []string{
				fmt.Sprintf("requires-%s", p.Name),
			},
		},
	}
}
