package app

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var errNotificationRecipientLimit = errors.New("현재 동적 수신자가 100명을 초과했습니다. 규칙 범위를 나누세요")

type notificationTarget struct {
	Address string
	UserID  string
}

func notificationUserCanRead(u User, entity, service domainResource) bool {
	scope := "services:read"
	if entity.Kind != "services" {
		scope = domainKinds[entity.Kind][0]
	}
	if !hasString(u.Scopes, "services:read") || !hasString(u.Scopes, scope) {
		return false
	}
	return elevated(u) || entity.OwnerID == u.ID || service.OwnerID == u.ID || u.Role == "lead" && u.Team != "" && u.Team == str(service.Data, "team")
}
func notificationCurrentUser(ctx context.Context, q notificationQuerier, id string) (User, error) {
	var u User
	err := q.QueryRow(ctx, `SELECT id,username,name,role,team FROM users WHERE id=$1 AND NOT disabled`, id).Scan(&u.ID, &u.Username, &u.Name, &u.Role, &u.Team)
	if err != nil {
		return u, err
	}
	if u.Role == "admin" {
		u.Scopes = append([]string{}, allScopes...)
	} else {
		cfg, e := notificationSetting(ctx, q, "roles")
		if e != nil {
			return u, e
		}
		u.Scopes = stringSlice(cfg[u.Role])
	}
	return u, nil
}
func (a *App) notificationTargets(ctx context.Context, q notificationQuerier, cfg notificationAutomation, rule notificationRule, channel NotificationChannel, entity, service domainResource, now time.Time) ([]notificationTarget, error) {
	targets := []notificationTarget{}
	seen := map[string]bool{}
	if cfg.Enabled && len(rule.RecipientSources) > 0 {
		var raw []byte
		err := q.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'username',username,'name',name,'role',role,'team',team)),'[]') FROM users WHERE NOT disabled AND id=ANY($1::text[])`, notificationContactIDs(cfg)).Scan(&raw)
		if err != nil {
			return nil, err
		}
		var users []User
		if err = json.Unmarshal(raw, &users); err != nil {
			return nil, err
		}
		roles, err := notificationSetting(ctx, q, "roles")
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			if u.Role == "admin" {
				u.Scopes = allScopes
			} else {
				u.Scopes = stringSlice(roles[u.Role])
			}
			if !notificationUserCanRead(u, entity, service) {
				continue
			}
			match := false
			for _, source := range rule.RecipientSources {
				switch source {
				case "assignee":
					match = match || str(entity.Data, "assignee") == u.ID || str(entity.Data, "assignee") == u.Username
				case "service_owner":
					match = match || service.OwnerID == u.ID
				case "team":
					match = match || u.Team != "" && u.Team == str(service.Data, "team")
				case "on_call":
					for _, d := range cfg.OnCall {
						if d.UserID == u.ID && d.Team == str(service.Data, "team") && !now.Before(d.StartsAt) && now.Before(d.EndsAt) {
							match = true
						}
					}
				}
			}
			if !match {
				continue
			}
			for _, contact := range cfg.Contacts {
				if contact.UserID != u.ID || !contact.Verified {
					continue
				}
				address := contact.WebhookID
				if channel.Type == "smtp" {
					address = contact.Email
				} else if channel.Type == "sms" || channel.Type == "kakao" {
					address = contact.Phone
				}
				if address == "" {
					continue
				}
				normal, e := validateNotificationRecipient(channel.Type, address)
				if e != nil {
					continue
				}
				key := strings.ToLower(normal)
				if !seen[key] {
					targets = append(targets, notificationTarget{normal, u.ID})
					seen[key] = true
				}
			}
		}
	}
	for _, address := range rule.Recipients {
		normal, err := validateNotificationRecipient(channel.Type, address)
		if err != nil {
			continue
		}
		key := strings.ToLower(normal)
		if !seen[key] {
			targets = append(targets, notificationTarget{normal, ""})
			seen[key] = true
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Address < targets[j].Address })
	if len(targets) > 100 {
		return nil, errNotificationRecipientLimit
	}
	return targets, nil
}
func notificationContactIDs(c notificationAutomation) []string {
	out := []string{}
	for _, v := range c.Contacts {
		if v.Verified {
			out = append(out, v.UserID)
		}
	}
	return out
}
func (a *App) notificationDynamicCurrent(ctx context.Context, q notificationQuerier, c *notificationClaim, entity, service domainResource) bool {
	if c.RecipientUserID == "" && c.AutomationRevision == nil {
		return true
	}
	cfg, revision, err := a.notificationAutomationConfig(ctx, q)
	if err != nil || !cfg.Enabled || c.AutomationRevision == nil || !revision.Equal(*c.AutomationRevision) {
		return false
	}
	if c.RecipientUserID == "" {
		return true
	}
	rule, err := a.notificationRule(ctx, q, c.RuleID)
	if err != nil {
		return false
	}
	targets, err := a.notificationTargets(ctx, q, cfg, rule, c.Channel, entity, service, time.Now())
	if err != nil {
		return false
	}
	for _, target := range targets {
		if target.UserID == c.RecipientUserID && strings.EqualFold(target.Address, c.Message.Recipient) {
			return true
		}
	}
	return false
}
func notificationResourcePair(ctx context.Context, q notificationQuerier, entityID, serviceID string) (domainResource, domainResource, error) {
	entity, e := scanResource(q.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE id=$1`, entityID))
	if e != nil {
		return entity, domainResource{}, e
	}
	service, e := scanResource(q.QueryRow(ctx, `SELECT id,kind,owner_id,data,created_at,updated_at FROM resources WHERE kind='services' AND id=$1`, serviceID))
	if e != nil {
		return entity, service, e
	}
	if entity.Kind == "services" && entity.ID != service.ID || entity.Kind != "services" && str(entity.Data, "service_id") != service.ID {
		return entity, service, pgx.ErrNoRows
	}
	return entity, service, nil
}
