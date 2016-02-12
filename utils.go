package main

import (
	"regexp"
	"strings"
)

var (
	// Regex for normalize query
	fixSpaces                    = regexp.MustCompile("\\s+")
	removesBadlyEscapedQuotes    = regexp.MustCompile("\\'")
	removesBadlyEscapedQuotesTwo = regexp.MustCompile("''('')+")
	removesHex                   = regexp.MustCompile("[^\x20-\x7e]")
	removesNumbers               = regexp.MustCompile("([^a-zA-Z0-9_\\$-])-?([0-9]+)")
)

// normalizeQuery is used on a raw query payload and returns a cleaned up query string.
func normalizeQuery(query string) string {
	normalizeQuery := query[1:]
	normalizeQuery = fixSpaces.ReplaceAllString(normalizeQuery, " ")
	normalizeQuery = removesBadlyEscapedQuotes.ReplaceAllString(normalizeQuery, "")
	normalizeQuery = removesBadlyEscapedQuotesTwo.ReplaceAllString(normalizeQuery, "")
	normalizeQuery = removesHex.ReplaceAllString(normalizeQuery, "")
	normalizeQuery = removesNumbers.ReplaceAllString(normalizeQuery, " 0 ")
	normalizeQuery = strings.Replace(normalizeQuery, "BDPE S", "", -1)
	return normalizeQuery
}
