package util

import (
	"fmt"
	"time"
)

type Time struct {
	Raw time.Time
}

func (t *Time) Sprint() string {
	return fmt.Sprint(t.Raw.Format(time.RFC3339))
}

func TimeFromUnix(unixTime uint32) Time {
	return Time{
		Raw: time.Unix(int64(unixTime), 0),
	}
}
