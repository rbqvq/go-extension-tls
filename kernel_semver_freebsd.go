package tls

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	_ "unsafe"

	"github.com/blang/semver/v4"
)

const (
	numbers  string = "0123456789"
	alphas          = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-"
	alphanum        = alphas + numbers
)

// Parse parses version string and returns a validated Version or error
// FreeBSD release version not contains patch
func parseVersion(s string) (semver.Version, error) {
	if len(s) == 0 {
		return semver.Version{}, errors.New("Version string empty")
	}

	// Split into major.(minor+pr+meta)
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return semver.Version{}, errors.New("No Major.Minor elements found")
	}

	// Major
	if !containsOnly(parts[0], numbers) {
		return semver.Version{}, fmt.Errorf("Invalid character(s) found in major number %q", parts[0])
	}
	if hasLeadingZeroes(parts[0]) {
		return semver.Version{}, fmt.Errorf("Major number must not contain leading zeroes %q", parts[0])
	}
	major, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return semver.Version{}, err
	}

	v := semver.Version{}
	v.Major = major

	var build, prerelease []string
	minorStr := parts[1]

	if buildIndex := strings.IndexRune(minorStr, '+'); buildIndex != -1 {
		build = strings.Split(minorStr[buildIndex+1:], ".")
		minorStr = minorStr[:buildIndex]
	}

	if preIndex := strings.IndexRune(minorStr, '-'); preIndex != -1 {
		prerelease = strings.Split(minorStr[preIndex+1:], ".")
		minorStr = minorStr[:preIndex]
	}

	if !containsOnly(minorStr, numbers) {
		return semver.Version{}, fmt.Errorf("Invalid character(s) found in minor number %q", minorStr)
	}
	if hasLeadingZeroes(minorStr) {
		return semver.Version{}, fmt.Errorf("Minor number must not contain leading zeroes %q", minorStr)
	}
	minor, err := strconv.ParseUint(minorStr, 10, 64)
	if err != nil {
		return semver.Version{}, err
	}

	v.Minor = minor

	// Prerelease
	for _, prstr := range prerelease {
		parsedPR, err := semver.NewPRVersion(prstr)
		if err != nil {
			return semver.Version{}, err
		}
		v.Pre = append(v.Pre, parsedPR)
	}

	// Build meta data
	for _, str := range build {
		if len(str) == 0 {
			return semver.Version{}, errors.New("Build meta data is empty")
		}
		if !containsOnly(str, alphanum) {
			return semver.Version{}, fmt.Errorf("Invalid character(s) found in build meta data %q", str)
		}
		v.Build = append(v.Build, str)
	}

	return v, nil
}

//go:linkname containsOnly github.com/blang/semver/v4.containsOnly
func containsOnly(s string, set string) bool

//go:linkname hasLeadingZeroes github.com/blang/semver/v4.hasLeadingZeroes
func hasLeadingZeroes(s string) bool
