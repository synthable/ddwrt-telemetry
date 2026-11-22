package main

import (
	"os"
	"regexp"
	"sort"
)

var validArchiveRe = regexp.MustCompile(`^(dns|fw-drop|fw-accept|syslog)-[0-9]{8}-[0-9]{6}\.log\.gz$`)

// listArchives returns a sorted, always non-nil slice of valid archive filenames
// in dir so JSON serialization produces [] rather than null when none exist.
func listArchives(dir string) []string {
	archives := make([]string, 0)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return archives
	}
	for _, e := range entries {
		if !e.IsDir() && validArchiveRe.MatchString(e.Name()) {
			archives = append(archives, e.Name())
		}
	}
	sort.Strings(archives)
	return archives
}
