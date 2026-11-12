package redact

import "regexp"

var promptNamedSecretRegex = regexp.MustCompile(`(?i)(password|api[_-]?key)\s*[:=]`)
