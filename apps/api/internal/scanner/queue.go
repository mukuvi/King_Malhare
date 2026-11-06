package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type Scope struct {
	AssetID          string   `json:"asset_id"`
	AuthorizationID  string   `json:"authorization_id"`
	AllowPrivate     bool     `json:"allow_private"`
	IntrusiveAllowed bool     `json:"intrusive_allowed"`
	ExpiresAt        string   `json:"expires_at"`
	AuthorizedHost   string   `json:"authorized_host"`
	AssetEnvironment string   `json:"asset_environment"`
	Reference        string   `json:"reference"`
	ApprovedTargets  []string `json:"approved_targets"`
}

type CloudCredential struct {
	Provider string            `json:"provider"`
	Fields   map[string]string `json:"fields"`
}

type Job struct {
	ScanID      string           `json:"scan_id"`
	OrgID       string           `json:"org_id"`
	Scanner     string           `json:"scanner"`
	Category    string           `json:"category"`
	Target      string           `json:"target"`
	TargetType  string           `json:"target_type"`
	Config      map[string]any   `json:"config"`
	Scope       Scope            `json:"scope"`
	Credentials *CloudCredential `json:"credentials,omitempty"`
	Attempt     int              `json:"attempt"`
	CreatedBy   string           `json:"created_by"`
	QueuedAt    string           `json:"queued_at"`
}

type Event struct {
	Type     string         `json:"type"`
	ScanID   string         `json:"scan_id"`
	Status   string         `json:"status,omitempty"`
	Phase    string         `json:"phase,omitempty"`
	Progress int            `json:"progress,omitempty"`
	Message  string         `json:"message,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
	At       time.Time      `json:"at"`
}

type Queue struct {
	rdb      *redis.Client
	key      string
	events   string
	orgLimit int
}

func NewQueue(rdb *redis.Client, key, events string) *Queue {
	return &Queue{rdb: rdb, key: key, events: events, orgLimit: 5000}
}

func (q *Queue) Enqueue(ctx context.Context, job Job) error {
	body, err := json.Marshal(job)
	if err != nil {
		return err
	}
	pipe := q.rdb.TxPipeline()
	pipe.LPush(ctx, q.key, body)
	pipe.LTrim(ctx, q.key, 0, int64(q.orgLimit-1))
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("enqueue scan: %w", err)
	}
	return nil
}

func (q *Queue) Publish(ctx context.Context, ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_ = q.rdb.Publish(ctx, q.events+":"+ev.ScanID, body).Err()
}

func (q *Queue) SetCancel(ctx context.Context, scanID string) error {
	return q.rdb.Set(ctx, "km:scan:cancel:"+scanID, "1", 24*time.Hour).Err()
}

func (q *Queue) IsCancelled(ctx context.Context, scanID string) (bool, error) {
	n, err := q.rdb.Exists(ctx, "km:scan:cancel:"+scanID).Result()
	return n > 0, err
}

func (q *Queue) SetEmergencyStop(ctx context.Context, orgID string, on bool) error {
	key := "km:org:emergency-stop:" + orgID
	if on {
		return q.rdb.Set(ctx, key, "1", 0).Err()
	}
	return q.rdb.Del(ctx, key).Err()
}

func (q *Queue) EmergencyStop(ctx context.Context, orgID string) (bool, error) {
	n, err := q.rdb.Exists(ctx, "km:org:emergency-stop:"+orgID).Result()
	return n > 0, err
}

func (q *Queue) QueueDepth(ctx context.Context) (int64, error) {
	return q.rdb.LLen(ctx, q.key).Result()
}

func (q *Queue) Heartbeats(ctx context.Context) ([]map[string]any, error) {
	keys, err := q.rdb.Keys(ctx, "km:worker:heartbeat:*").Result()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		raw, err := q.rdb.Get(ctx, k).Result()
		if err != nil {
			continue
		}
		var hb map[string]any
		if json.Unmarshal([]byte(raw), &hb) == nil {
			out = append(out, hb)
		}
	}
	return out, nil
}

func (q *Queue) RateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	pipe := q.rdb.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return true, limit, err
	}
	n := int(incr.Val())
	return n <= limit, max(0, limit-n), nil
}

func (q *Queue) Raw() *redis.Client { return q.rdb }
