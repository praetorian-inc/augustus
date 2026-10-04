package mcpprobe

import (
	"errors"
	"net/url"
	"strings"
)

// RedactEndpoint returns raw with credential carriers removed, for errors,
// logs and reports. The whole userinfo goes, not just the password: a bare
// username is often a token. Query values become "<redacted>" (names are kept
// so the target's shape stays visible): servers accept tokens such as
// ?access_token= there. The fragment goes for the same reason.
func RedactEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(malformed URL)"
	}
	u.User = nil
	if u.RawQuery != "" {
		q, qerr := url.ParseQuery(u.RawQuery)
		if qerr != nil {
			u.RawQuery = "<redacted>"
		} else {
			for k := range q {
				q[k] = []string{"<redacted>"}
			}
			u.RawQuery = q.Encode()
		}
	}
	u.Fragment, u.RawFragment = "", ""
	return u.String()
}

// RedactURLError returns err with the userinfo of any wrapped *url.Error URL
// removed from its text. net/http masks only the password ("user:***@"), so a
// bare-username token would otherwise reach errors and logs. errors.Is and
// errors.As still see the original chain. Errors without a *url.Error are
// returned unchanged.
func RedactURLError(err error) error {
	var ue *url.Error
	if err == nil || !errors.As(err, &ue) {
		return err
	}
	clean := RedactEndpoint(ue.URL)
	forms := []string{ue.URL}
	if u, perr := url.Parse(ue.URL); perr == nil && u.User != nil {
		forms = append(forms, u.String(), u.Redacted())
		if _, ok := u.User.Password(); ok {
			// Same masking as net/http's stripPassword.
			forms = append(forms, strings.Replace(u.String(), u.User.String()+"@", u.User.Username()+":***@", 1))
		}
	}
	return &redactedURLError{err: err, forms: forms, clean: clean}
}

type redactedURLError struct {
	err   error
	forms []string
	clean string
}

func (e *redactedURLError) Error() string {
	msg := e.err.Error()
	for _, f := range e.forms {
		if f != "" && f != e.clean {
			msg = strings.ReplaceAll(msg, f, e.clean)
		}
	}
	return msg
}

func (e *redactedURLError) Unwrap() error { return e.err }
