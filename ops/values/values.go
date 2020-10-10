// Package values provides Go value wrappers that can encode/decode from JSON.
package values

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Time provides a Time type that can encode/decode from JSON integers representing Unix Epoch.
// Implements json.Marshaller and json.Unmarshaller.
type Time time.Time

// Time returns the Go native time.Time.
func (t Time) Time() time.Time {
	return time.Time(t)
}

func (t Time) String() string {
	return t.Time().String()
}

func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(time.Time(t).Unix(), 10)), nil
}

func (t *Time) UnmarshalJSON(s []byte) error {
	r := string(s)
	q, err := strconv.ParseInt(r, 10, 64)
	if err != nil {
		return err
	}
	*(*time.Time)(t) = time.Unix(q, 0)
	return nil
}

// URL provides a URL type that can encode/decode from JSON strings.
// Implements json.Marshaller and json.Unmarshaller.
type URL url.URL

// URL returns the Go native *url.URL.
func (u *URL) URL() *url.URL {
	if u == nil {
		return nil
	}
	return (*url.URL)(u)
}

func (u *URL) String() string {
	if u == nil {
		return ""
	}
	return u.URL().String()
}

func (u *URL) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", (*url.URL)(u).String())), nil
}

func (u *URL) UnmarshalJSON(s []byte) error {
	if len(s) == 0 {
		u = &URL{}
		return nil
	}
	ur, err := url.Parse(string(s))
	if err != nil {
		return err
	}
	u = (*URL)(ur)
	return nil
}
