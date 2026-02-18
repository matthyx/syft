package dependency

import (
	"fmt"
	"sort"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/scylladb/go-set/strset"
)

func BenchmarkDeduplicate(b *testing.B) {
	input := generateDuplicateStrings(100, 50)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deduplicate(input)
	}
}

func BenchmarkDeduplicate_Old(b *testing.B) {
	input := generateDuplicateStrings(100, 50)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deduplicateOld(input)
	}
}

func BenchmarkDeduplicate_New(b *testing.B) {
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

func BenchmarkDeduplicate_Large_Old(b *testing.B) {
	input := generateDuplicateStrings(1000, 200)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deduplicateOld(input)
	}
}

func BenchmarkDeduplicate_Large_New(b *testing.B) {
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

func BenchmarkDeduplicate_VeryLarge_Old(b *testing.B) {
	input := generateDuplicateStrings(5000, 500)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deduplicateOld(input)
	}
}

func BenchmarkDeduplicate_VeryLarge_New(b *testing.B) {
	input := generateDuplicateStrings(5000, 500)

	b.ReportAllocs()
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

func BenchmarkResolve_CraftedRelationships_VeryLarge_Old(b *testing.B) {
	pkgs := generatePackages(1000, 500)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ResolveOld(testDependencySpecifier, pkgs)
	}
}

func BenchmarkResolve_CraftedRelationships_VeryLarge_New(b *testing.B) {
	pkgs := generatePackages(1000, 500)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Resolve(testDependencySpecifier, pkgs)
	}
}

func deduplicateOld(ss []string) []string {
	set := strset.New(ss...)
	list := set.List()
	sort.Strings(list)
	return list
}

// ResolveOld is the old implementation using string concatenation and strset
func ResolveOld(specifier Specifier, pkgs []pkg.Package) (relationships []artifact.Relationship) {
	pkgsProvidingResource := make(map[string]*strset.Set)

	pkgsByID := make(map[artifact.ID]pkg.Package)
	specsByPkg := make(map[artifact.ID][]ProvidesRequires)

	for _, p := range pkgs {
		id := p.ID()
		pkgsByID[id] = p
		specsByPkg[id] = allProvidesOld(pkgsProvidingResource, id, specifier(p))
	}

	seen := strset.New()
	for _, dependantPkg := range pkgs {
		specs := specsByPkg[dependantPkg.ID()]
		for _, spec := range specs {
			for _, resource := range deduplicateOld(spec.Requires) {
				if pkgsProvidingResource[resource] != nil {
					for _, providingPkgIDStr := range pkgsProvidingResource[resource].List() {
						fromID := artifact.ID(providingPkgIDStr)
						toID := dependantPkg.ID()

						key := string(fromID) + "->" + string(toID)
						if seen.Has(key) {
							continue
						}

						providingPkg := pkgsByID[fromID]

						relationships = append(relationships,
							artifact.Relationship{
								From: providingPkg,
								To:   dependantPkg,
								Type: artifact.DependencyOfRelationship,
							},
						)

						seen.Add(key)
					}
				}
			}
		}
	}
	return relationships
}

func allProvidesOld(pkgsProvidingResource map[string]*strset.Set, id artifact.ID, spec Specification) []ProvidesRequires {
	prs := []ProvidesRequires{spec.ProvidesRequires}
	prs = append(prs, spec.Variants...)

	for _, pr := range prs {
		for _, resource := range deduplicateOld(pr.Provides) {
			if pkgsProvidingResource[resource] == nil {
				pkgsProvidingResource[resource] = strset.New()
			}
			pkgsProvidingResource[resource].Add(string(id))
		}
	}

	return prs
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
