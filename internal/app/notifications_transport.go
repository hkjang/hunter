package app

// Notification transports send one immutable delivery to one recipient. A
// successful return means that the relay accepted the request, not that the
// person has received or read it. Provider response bodies are never logged.
import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

var notificationFieldPath = regexp.MustCompile(`^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*$`)
var notificationHeaderName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
var notificationReceiptID = regexp.MustCompile(`^[a-zA-Z0-9_.:/-]{1,200}$`)

func notificationTimeout(c map[string]any) time.Duration {
	n := asInt(c["timeout_seconds"])
	if n == 0 {
		n = 20
	}
	return time.Duration(n) * time.Second
}

func validateNotificationRecipient(kind, raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 320 || strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("수신자를 확인해 주세요")
	}
	switch kind {
	case "smtp":
		addr, err := mail.ParseAddress(s)
		if err != nil || !strings.Contains(addr.Address, "@") || strings.IndexFunc(addr.Address, func(r rune) bool { return r > 127 || unicode.IsControl(r) }) >= 0 {
			return "", errors.New("수신자마다 이메일 주소 하나를 입력해 주세요")
		}
		return addr.Address, nil
	case "sms", "kakao":
		s = strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(s)
		digits := strings.TrimPrefix(s, "+")
		if len(digits) < 8 || len(digits) > 16 || strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return "", errors.New("문자·카카오톡 수신자는 8~16자리 전화번호로 입력해 주세요")
		}
		return s, nil
	case "webhook":
		if len(s) > 200 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
			return "", errors.New("API 수신 식별자는 200바이트 이하로 입력해 주세요")
		}
		return s, nil
	}
	return "", errors.New("지원하지 않는 발송 채널입니다")
}

func notificationHeaders(v any) (map[string]string, error) {
	if v == nil {
		return map[string]string{}, nil
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 16384 {
		return nil, errors.New("헤더는 16 KiB 이하의 문자열 객체여야 합니다")
	}
	var headers map[string]string
	if json.Unmarshal(raw, &headers) != nil || headers == nil || len(headers) > 30 {
		return nil, errors.New("헤더는 최대 30개의 문자열 객체여야 합니다")
	}
	seen := map[string]bool{}
	for name, value := range headers {
		key := strings.ToLower(name)
		if !notificationHeaderName.MatchString(name) || seen[key] || len(value) > 4096 || strings.IndexFunc(value, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return nil, errors.New("헤더 이름·값·대소문자 중복을 확인해 주세요")
		}
		seen[key] = true
		switch key {
		case "host", "content-length", "transfer-encoding", "connection", "upgrade", "proxy-authorization", "proxy-connection", "trailer", "te", "content-type":
			return nil, errors.New("전송 경로나 본문 형식을 바꾸는 헤더는 지정할 수 없습니다")
		}
	}
	return headers, nil
}

func (a *App) validateNotificationTransport(channel NotificationChannel) error {
	c := channel.Config
	if c == nil {
		return errors.New("연동 설정을 입력해 주세요")
	}
	allowed := map[string]bool{"timeout_seconds": true}
	var fields []string
	if channel.Type == "smtp" {
		fields = []string{"host", "port", "security", "from", "username", "auth"}
	} else if hasString([]string{"sms", "kakao", "webhook"}, channel.Type) {
		fields = []string{"endpoint", "method", "format", "auth", "username", "auth_header", "headers", "body_template", "success_path", "success_value", "id_path", "idempotency_header", "idempotency_supported"}
	} else {
		return errors.New("SMTP·문자·카카오톡·HTTP 중 발송 채널을 선택해 주세요")
	}
	for _, k := range fields {
		allowed[k] = true
	}
	for k := range c {
		if !allowed[k] {
			return fmt.Errorf("지원하지 않는 연동 설정 항목: %s", k)
		}
	}
	for k, v := range c {
		if hasString([]string{"port", "timeout_seconds", "headers", "body_template", "success_value", "idempotency_supported"}, k) {
			continue
		}
		if _, ok := v.(string); !ok {
			return errors.New("연동 설정의 문자열 항목을 확인해 주세요")
		}
	}
	if v, ok := c["timeout_seconds"]; ok {
		n := asInt(v)
		if n < 1 || n > 30 || fmt.Sprint(v) != strconv.Itoa(n) {
			return errors.New("연결 시간 제한은 1~30초 정수로 입력해 주세요")
		}
	}
	if len(channel.Secret) > 16384 {
		return errors.New("인증 비밀값은 16 KiB 이하여야 합니다")
	}
	if channel.Type == "smtp" {
		host := str(c, "host")
		if host == "" || len(host) > 253 || strings.ContainsAny(host, "/@?#{}[] \\") || strings.IndexFunc(host, unicode.IsControl) >= 0 || strings.Contains(host, ":") && net.ParseIP(host) == nil {
			return errors.New("SMTP 호스트는 프로토콜·포트를 제외한 호스트명 또는 IP로 입력해 주세요")
		}
		port := asInt(c["port"])
		if port < 1 || port > 65535 || fmt.Sprint(c["port"]) != strconv.Itoa(port) {
			return errors.New("SMTP 포트는 1~65535 정수로 입력해 주세요")
		}
		security := str(c, "security")
		if !hasString([]string{"starttls", "tls", "none"}, security) {
			return errors.New("SMTP 보안 방식을 선택해 주세요")
		}
		if _, err := validateNotificationRecipient("smtp", str(c, "from")); err != nil {
			return errors.New("SMTP 발신 이메일 주소를 확인해 주세요")
		}
		if security == "none" && (str(c, "username") != "" || channel.Secret != "") {
			return errors.New("암호화 없는 사내 SMTP 릴레이에서는 인증 정보를 사용할 수 없습니다")
		}
		if auth := str(c, "auth"); auth != "" && auth != "plain" && auth != "login" {
			return errors.New("SMTP 인증은 PLAIN 또는 LOGIN을 선택해 주세요")
		}
		if strings.ContainsAny(str(c, "username"), "\r\n\x00") || len(str(c, "username")) > 320 {
			return errors.New("SMTP 인증 사용자 이름을 확인해 주세요")
		}
		return nil
	}
	u, err := parseTarget(str(c, "endpoint"))
	if err != nil || u.Hostname() == "" || strings.ContainsAny(str(c, "endpoint"), "{}") || len(str(c, "endpoint")) > 4096 {
		return errors.New("API 주소는 고정된 HTTP(S) 주소로 입력해 주세요")
	}
	if method := str(c, "method"); method != "" && method != "POST" && method != "PUT" {
		return errors.New("API 발송 메서드는 POST 또는 PUT을 선택해 주세요")
	}
	format := str(c, "format")
	if format != "" && format != "json" && format != "form" {
		return errors.New("API 본문 형식은 JSON 또는 폼을 선택해 주세요")
	}
	auth := str(c, "auth")
	if !hasString([]string{"", "none", "bearer", "basic", "header", "headers", "ncp"}, auth) {
		return errors.New("API 인증 방식을 확인해 주세요")
	}
	if auth == "basic" && strings.Contains(str(c, "username"), ":") {
		return errors.New("Basic 인증 사용자 이름에 콜론을 사용할 수 없습니다")
	}
	if auth == "header" {
		if str(c, "auth_header") == "" {
			return errors.New("인증 헤더 이름을 입력해 주세요")
		}
		if _, err := notificationHeaders(map[string]string{str(c, "auth_header"): "value"}); err != nil {
			return err
		}
	}
	if auth == "headers" && channel.Secret != "" {
		var values any
		if json.Unmarshal([]byte(channel.Secret), &values) != nil {
			return errors.New("인증 헤더 비밀값은 JSON 문자열 객체로 입력해 주세요")
		}
		if _, err := notificationHeaders(values); err != nil {
			return err
		}
	} else if auth != "basic" && strings.IndexFunc(channel.Secret, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return errors.New("인증 비밀값에 줄바꿈이나 제어 문자를 사용할 수 없습니다")
	}
	if auth == "ncp" && (str(c, "username") == "" || format == "form") {
		return errors.New("NCP 서명에는 Access Key와 JSON 본문이 필요합니다")
	}
	if strings.IndexFunc(str(c, "username"), unicode.IsControl) >= 0 || len(str(c, "username")) > 1000 {
		return errors.New("API 인증 사용자 이름을 확인해 주세요")
	}
	headers, err := notificationHeaders(c["headers"])
	if err != nil {
		return err
	}
	for k := range headers {
		low := strings.ToLower(k)
		if strings.Contains(low, "authorization") || strings.Contains(low, "secret") || strings.Contains(low, "token") || strings.Contains(low, "api-key") || strings.Contains(low, "api_key") || low == "cookie" {
			return errors.New("인증 헤더는 일반 헤더 대신 인증 비밀값 항목에 입력해 주세요")
		}
	}
	for _, k := range []string{"success_path", "id_path"} {
		if path := str(c, k); path != "" && (len(path) > 200 || !notificationFieldPath.MatchString(path)) {
			return errors.New("응답 경로는 점으로 구분한 필드·배열 번호로 입력해 주세요")
		}
	}
	if value, ok := c["success_value"]; ok {
		switch value.(type) {
		case string, float64, int, bool, json.Number:
		default:
			return errors.New("응답 성공 값은 문자열·숫자·참거짓이어야 합니다")
		}
	}
	if str(c, "success_path") != "" && c["success_value"] == nil {
		return errors.New("응답 성공 경로와 비교 값을 함께 입력해 주세요")
	}
	if v, ok := c["idempotency_supported"]; ok {
		if _, good := v.(bool); !good {
			return errors.New("중복 방지 지원 여부는 참거짓이어야 합니다")
		}
	}
	if h := str(c, "idempotency_header"); h != "" {
		if _, err := notificationHeaders(map[string]string{h: "value"}); err != nil {
			return err
		}
		if strings.EqualFold(h, "Cookie") || strings.EqualFold(h, "Authorization") || strings.EqualFold(h, str(c, "auth_header")) || strings.HasPrefix(strings.ToLower(h), "x-ncp-") {
			return errors.New("중복 방지 헤더는 인증 헤더와 달라야 합니다")
		}
		if auth == "headers" && channel.Secret != "" {
			var secretHeaders map[string]string
			_ = json.Unmarshal([]byte(channel.Secret), &secretHeaders)
			for key := range secretHeaders {
				if strings.EqualFold(h, key) {
					return errors.New("중복 방지 헤더는 인증 헤더와 달라야 합니다")
				}
			}
		}
	}
	if boolean(c, "idempotency_supported") && str(c, "idempotency_header") == "" {
		return errors.New("중복 방지를 지원하는 API의 요청 식별자 헤더를 입력해 주세요")
	}
	tpl := c["body_template"]
	if tpl == nil {
		tpl = notificationDefaultPayload()
	}
	b, err := json.Marshal(tpl)
	if err != nil || len(b) > 65536 {
		return errors.New("API 본문 템플릿은 64 KiB 이하여야 합니다")
	}
	if _, ok := tpl.(map[string]any); !ok {
		if _, ok = tpl.(map[string]string); !ok {
			return errors.New("API 본문 템플릿은 JSON 객체여야 합니다")
		}
	}
	var normalized any
	_ = json.Unmarshal(b, &normalized)
	if format == "form" {
		for _, v := range normalized.(map[string]any) {
			if _, ok := v.(string); !ok {
				return errors.New("폼 본문은 문자열 값으로 구성한 객체여야 합니다")
			}
		}
	}
	_, err = renderNotificationPayload(normalized, notificationTransportSample())
	return err
}

func notificationDefaultPayload() map[string]any {
	return map[string]any{"to": "{{message.recipient}}", "subject": "{{message.subject}}", "message": "{{message.body}}", "eventId": "{{message.id}}"}
}

func notificationTransportSample() NotificationMessage {
	vars := map[string]string{}
	for _, key := range notificationVariables {
		vars[key] = "예시"
	}
	return NotificationMessage{DeliveryID: "sample", EventID: "sample", Recipient: "sample", Subject: "미리보기", Body: "연결 테스트", Variables: vars}
}

func notificationMessageValues(m NotificationMessage) map[string]string {
	values := map[string]string{}
	for k, v := range m.Variables {
		values[k] = v
	}
	values["message.id"], values["message.event_id"] = m.DeliveryID, m.EventID
	values["message.recipient"], values["message.subject"], values["message.body"] = m.Recipient, m.Subject, m.Body
	return values
}

func renderNotificationPayload(value any, m NotificationMessage) (any, error) {
	values := notificationMessageValues(m)
	var render func(any) (any, error)
	render = func(value any) (any, error) {
		switch v := value.(type) {
		case string:
			var missing bool
			out := notificationPlaceholder.ReplaceAllStringFunc(v, func(key string) string {
				name := notificationPlaceholder.FindStringSubmatch(key)[1]
				result, ok := values[name]
				if !ok {
					missing = true
				}
				return result
			})
			// Detect malformed placeholders in the template, never interpret braces
			// from a substituted message as more template instructions.
			remainder := notificationPlaceholder.ReplaceAllString(v, "")
			if missing || strings.Contains(remainder, "{{") || strings.Contains(remainder, "}}") {
				return nil, errors.New("알 수 없거나 올바르지 않은 알림 템플릿 변수가 있습니다")
			}
			return out, nil
		case map[string]any:
			out := map[string]any{}
			for k, child := range v {
				if strings.Contains(k, "{{") || strings.Contains(k, "}}") {
					return nil, errors.New("API 본문 필드 이름에는 템플릿 변수를 사용할 수 없습니다")
				}
				result, err := render(child)
				if err != nil {
					return nil, err
				}
				out[k] = result
			}
			return out, nil
		case []any:
			out := make([]any, len(v))
			for i, child := range v {
				result, err := render(child)
				if err != nil {
					return nil, err
				}
				out[i] = result
			}
			return out, nil
		default:
			return value, nil
		}
	}
	return render(value)
}

func (a *App) sendNotification(ctx context.Context, channel NotificationChannel, message NotificationMessage) NotificationSendResult {
	if err := a.validateNotificationTransport(channel); err != nil {
		return NotificationSendResult{State: "failed", Code: "configuration", Detail: "발송 채널 설정을 확인해 주세요"}
	}
	recipient, err := validateNotificationRecipient(channel.Type, message.Recipient)
	if err != nil {
		return NotificationSendResult{State: "failed", Code: "recipient", Detail: "수신자 형식을 확인해 주세요"}
	}
	message.Recipient = recipient
	if len(message.Subject) > 4000 || len(message.Body) > 131072 || strings.ContainsAny(message.Subject, "\r\n\x00") || strings.ContainsRune(message.Body, '\x00') {
		return NotificationSendResult{State: "failed", Code: "message", Detail: "알림 제목·본문의 형식과 크기를 확인해 주세요"}
	}
	ctx, cancel := context.WithTimeout(ctx, notificationTimeout(channel.Config))
	defer cancel()
	if channel.Type == "smtp" {
		return a.sendSMTPNotification(ctx, channel, message)
	}
	return a.sendHTTPNotification(ctx, channel, message)
}

func (a *App) sendHTTPNotification(ctx context.Context, channel NotificationChannel, message NotificationMessage) NotificationSendResult {
	c := channel.Config
	tpl := c["body_template"]
	if tpl == nil {
		tpl = notificationDefaultPayload()
	}
	b, _ := json.Marshal(tpl)
	var normalized any
	_ = json.Unmarshal(b, &normalized)
	payload, err := renderNotificationPayload(normalized, message)
	if err != nil {
		return NotificationSendResult{State: "failed", Code: "template", Detail: "알림 템플릿 변수를 확인해 주세요"}
	}
	contentType := "application/json; charset=utf-8"
	if str(c, "format") == "form" {
		form := url.Values{}
		for k, v := range payload.(map[string]any) {
			form.Set(k, asString(v))
		}
		b = []byte(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	} else {
		b, err = json.Marshal(payload)
	}
	if err != nil || len(b) > 262144 {
		return NotificationSendResult{State: "failed", Code: "payload", Detail: "생성한 API 본문이 256 KiB를 초과했습니다"}
	}
	client, err := a.outboundClient(ctx, notificationTimeout(c))
	if err != nil {
		return NotificationSendResult{State: "failed", Code: "ca", Detail: "사내 CA 인증서 설정을 확인해 주세요"}
	}
	defer client.CloseIdleConnections()
	method := defaultString(str(c, "method"), "POST")
	var wroteHeaders atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteHeaders: func() { wroteHeaders.Store(true) }})
	req, err := http.NewRequestWithContext(ctx, method, str(c, "endpoint"), bytes.NewReader(b))
	if err != nil {
		return NotificationSendResult{State: "failed", Code: "endpoint", Detail: "API 주소를 확인해 주세요"}
	}
	// Retry only through the persisted queue, never via an invisible HTTP replay.
	req.GetBody = nil
	headers, _ := notificationHeaders(c["headers"])
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	auth := str(c, "auth")
	if auth != "" && auth != "none" && channel.Secret == "" {
		return NotificationSendResult{State: "failed", Code: "credentials", Detail: "API 인증 비밀값을 등록해 주세요"}
	}
	switch auth {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+channel.Secret)
	case "basic":
		req.SetBasicAuth(str(c, "username"), channel.Secret)
	case "header":
		req.Header.Set(str(c, "auth_header"), channel.Secret)
	case "headers":
		var secretHeaders map[string]string
		_ = json.Unmarshal([]byte(channel.Secret), &secretHeaders)
		for k, v := range secretHeaders {
			req.Header.Set(k, v)
		}
	case "ncp":
		stamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		access := str(c, "username")
		mac := hmac.New(sha256.New, []byte(channel.Secret))
		_, _ = io.WriteString(mac, method+" "+req.URL.RequestURI()+"\n"+stamp+"\n"+access)
		req.Header.Set("x-ncp-apigw-timestamp", stamp)
		req.Header.Set("x-ncp-iam-access-key", access)
		req.Header.Set("x-ncp-apigw-signature-v2", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	}
	if h := str(c, "idempotency_header"); h != "" {
		req.Header.Set(h, "hunter-"+message.DeliveryID)
	}
	resp, err := client.Do(req)
	if err != nil {
		state := "uncertain"
		if !wroteHeaders.Load() || boolean(c, "idempotency_supported") {
			state = "retryable"
		}
		return NotificationSendResult{State: state, Code: "connection", Detail: "API 연결 또는 응답 확인에 실패했습니다. 접수 여부를 확인해 주세요"}
	}
	defer resp.Body.Close()
	code := strconv.Itoa(resp.StatusCode)
	if resp.StatusCode == 429 {
		return NotificationSendResult{State: "retryable", Code: code, Detail: "API 요청 한도를 초과했습니다", RetryAfter: notificationRetryAfter(resp.Header.Get("Retry-After"))}
	}
	if resp.StatusCode >= 500 || resp.StatusCode == 408 {
		state := "uncertain"
		if boolean(c, "idempotency_supported") {
			state = "retryable"
		}
		return NotificationSendResult{State: state, Code: code, Detail: "API 서버 오류로 접수 여부 확인이 필요합니다"}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return NotificationSendResult{State: "failed", Code: code, Detail: "API가 요청을 거부했습니다. 인증·주소·요청 규격을 확인해 주세요"}
	}
	result := NotificationSendResult{State: "sent", Code: code, Detail: "API가 전달 요청을 접수했습니다"}
	if str(c, "success_path") == "" && str(c, "id_path") == "" {
		return result
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	var response any
	if err != nil || len(raw) > 65536 || json.Unmarshal(raw, &response) != nil {
		if str(c, "success_path") == "" {
			return result
		}
		return NotificationSendResult{State: "uncertain", Code: code, Detail: "API 응답의 성공 조건을 확인할 수 없습니다"}
	}
	if path := str(c, "success_path"); path != "" {
		value, ok := notificationResponseValue(response, path)
		if !ok {
			return NotificationSendResult{State: "uncertain", Code: code, Detail: "API 응답에 설정한 성공 필드가 없습니다"}
		}
		if fmt.Sprint(value) != fmt.Sprint(c["success_value"]) {
			return NotificationSendResult{State: "failed", Code: code, Detail: "API 응답이 설정한 성공 조건을 충족하지 않았습니다"}
		}
	}
	if path := str(c, "id_path"); path != "" {
		if id, ok := notificationResponseValue(response, path); ok {
			value := fmt.Sprint(id)
			if notificationSafeReceipt(value, channel, message) {
				result.ProviderID = value
			}
		}
	}
	return result
}

func notificationSafeReceipt(value string, channel NotificationChannel, message NotificationMessage) bool {
	if !notificationReceiptID.MatchString(value) || notificationText(value, 200) != value {
		return false
	}
	secrets := []string{message.Recipient}
	if str(channel.Config, "auth") == "headers" {
		var headers map[string]string
		_ = json.Unmarshal([]byte(channel.Secret), &headers)
		for _, secret := range headers {
			secrets = append(secrets, secret)
		}
	} else {
		secrets = append(secrets, channel.Secret)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(value, secret) {
			return false
		}
	}
	return true
}

func notificationResponseValue(value any, path string) (any, bool) {
	for _, part := range strings.Split(path, ".") {
		switch v := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = v[part]
			if !ok {
				return nil, false
			}
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) {
				return nil, false
			}
			value = v[i]
		default:
			return nil, false
		}
	}
	switch value.(type) {
	case string, float64, bool:
		return value, true
	default:
		return nil, false
	}
}

func notificationRetryAfter(value string) time.Duration {
	var delay time.Duration
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil {
		delay = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(value); err == nil {
		delay = time.Until(at)
	}
	if delay < time.Second {
		delay = time.Second
	}
	if delay > time.Hour {
		delay = time.Hour
	}
	return delay
}

type notificationLoginAuth struct {
	username, password, host string
	step                     int
}

func (a *notificationLoginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS || server.Name != a.host {
		return "", nil, errors.New("SMTP LOGIN requires verified TLS")
	}
	a.step = 0
	return "LOGIN", nil, nil
}
func (a *notificationLoginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	if a.step == 1 {
		return []byte(a.username), nil
	}
	if a.step == 2 {
		return []byte(a.password), nil
	}
	return nil, errors.New("unexpected SMTP LOGIN challenge")
}

func notificationSMTPError(err error, afterData bool) NotificationSendResult {
	state, code := "retryable", "smtp_connection"
	var protocol *textproto.Error
	if errors.As(err, &protocol) {
		code = strconv.Itoa(protocol.Code)
		if protocol.Code >= 500 {
			state = "failed"
		} else if protocol.Code < 400 {
			state = "uncertain"
		}
	} else if afterData {
		state = "uncertain"
	}
	return NotificationSendResult{State: state, Code: code, Detail: "SMTP 전송에 실패했습니다. 릴레이 접수 여부와 연결 설정을 확인해 주세요"}
}

func (a *App) sendSMTPNotification(ctx context.Context, channel NotificationChannel, message NotificationMessage) NotificationSendResult {
	c := channel.Config
	host := str(c, "host")
	from, _ := mail.ParseAddress(str(c, "from"))
	roots, err := a.trustedRoots(ctx)
	if err != nil {
		return NotificationSendResult{State: "failed", Code: "ca", Detail: "사내 CA 인증서 설정을 확인해 주세요"}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: host}
	dialer := net.Dialer{Timeout: notificationTimeout(c)}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(asInt(c["port"]))))
	if err != nil {
		return notificationSMTPError(err, false)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if str(c, "security") == "tls" {
		tlsConn := tls.Client(conn, tlsConfig)
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			return NotificationSendResult{State: "failed", Code: "tls", Detail: "SMTP TLS 연결 또는 인증서 검증에 실패했습니다"}
		}
		conn = tlsConn
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return notificationSMTPError(err, false)
	}
	defer client.Close()
	if err = client.Hello("hunter.local"); err != nil {
		return notificationSMTPError(err, false)
	}
	if str(c, "security") == "starttls" {
		if supported, _ := client.Extension("STARTTLS"); !supported {
			return NotificationSendResult{State: "failed", Code: "starttls_required", Detail: "SMTP 서버가 필수 STARTTLS를 지원하지 않습니다"}
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return NotificationSendResult{State: "failed", Code: "tls", Detail: "SMTP STARTTLS 또는 인증서 검증에 실패했습니다"}
		}
	}
	if username := str(c, "username"); username != "" {
		if channel.Secret == "" {
			return NotificationSendResult{State: "failed", Code: "credentials", Detail: "SMTP 인증 비밀번호를 등록해 주세요"}
		}
		var auth smtp.Auth = smtp.PlainAuth("", username, channel.Secret, host)
		if str(c, "auth") == "login" {
			auth = &notificationLoginAuth{username: username, password: channel.Secret, host: host}
		}
		if err = client.Auth(auth); err != nil {
			return notificationSMTPError(err, false)
		}
	}
	if err = client.Mail(from.Address); err != nil {
		return notificationSMTPError(err, false)
	}
	if err = client.Rcpt(message.Recipient); err != nil {
		return notificationSMTPError(err, false)
	}
	writer, err := client.Data()
	if err != nil {
		return notificationSMTPError(err, false)
	}
	msgID := "hunter-" + digest(message.DeliveryID)[:32] + "@hunter.local"
	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", from.String(), (&mail.Address{Address: message.Recipient}).String(), mime.QEncoding.Encode("UTF-8", message.Subject), time.Now().Format(time.RFC1123Z), msgID)
	if _, err = io.WriteString(writer, headers); err != nil {
		return notificationSMTPError(err, true)
	}
	qp := quotedprintable.NewWriter(writer)
	if _, err = io.WriteString(qp, message.Body); err != nil {
		return notificationSMTPError(err, true)
	}
	if err = qp.Close(); err != nil {
		return notificationSMTPError(err, true)
	}
	if err = writer.Close(); err != nil {
		return notificationSMTPError(err, true)
	}
	// DATA has been accepted. A later QUIT/connection error cannot unsend it.
	_ = client.Quit()
	return NotificationSendResult{State: "sent", ProviderID: msgID, Code: "250", Detail: "SMTP 릴레이가 메일을 접수했습니다"}
}
