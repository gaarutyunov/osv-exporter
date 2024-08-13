package main

import "regexp"

var commitRegExp = regexp.MustCompile(`https://github\.com/(?P<org>.*)/(?P<repo>.*)/commit/(?P<commit>.{40})`)

func regexpSearch(pattern *regexp.Regexp, s string) (res map[string]string, ok bool) {
	match := pattern.FindStringSubmatch(s)

	if match == nil {
		return nil, false
	}

	res = make(map[string]string, len(pattern.SubexpNames()))

	for i, name := range pattern.SubexpNames() {
		if i == 0 || name == "" {
			continue
		}
		res[name] = match[i]
	}

	return res, true
}
