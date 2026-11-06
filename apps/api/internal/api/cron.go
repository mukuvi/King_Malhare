package api

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

func nextCron(expr string, from time.Time) (time.Time, error) {
	expr = trimSpace(expr)
	if expr == "" {
		return time.Time{}, fmt.Errorf("empty expression")
	}
	schedule, err := cron.ParseStandard(expr)
	if err != nil {
		return time.Time{}, err
	}
	next := schedule.Next(from.UTC())
	if next.IsZero() || next.After(from.AddDate(1, 0, 0)) {
		return time.Time{}, fmt.Errorf("next run is more than a year away")
	}
	return next, nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
