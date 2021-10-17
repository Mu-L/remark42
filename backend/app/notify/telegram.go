package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/microcosm-cc/bluemonday"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/repeater"
	"github.com/pkg/errors"
)

// TelegramParams contain settings for telegram notifications
type TelegramParams struct {
	AdminChannelID       string        // unique identifier for the target chat or username of the target channel (in the format @channelusername)
	Token                string        // token for telegram bot API interactions
	Timeout              time.Duration // http client timeout
	UserNotifications    bool          // flag which enables user notifications
	ErrorMsg, SuccessMsg string        // messages for successful and unsuccessful subscription requests to bot

	apiPrefix string // changed only in tests
}

// Telegram implements notify.Destination for telegram
type Telegram struct {
	TelegramParams

	// Identifier of the first update to be requested.
	// Should be equal to LastSeenUpdateID + 1
	// See https://core.telegram.org/bots/api#getupdates
	updateOffset   int
	tgPollInterval time.Duration
	username       string // bot username
	requests       struct {
		sync.RWMutex
		data map[string]tgAuthRequest
	}
}

// telegramMsg is used to send message trough Telegram bot API
type telegramMsg struct {
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode,omitempty"`
}

type tgAuthRequest struct {
	confirmed  bool // whether login request has been confirmed and user info set
	expires    time.Time
	telegramID string
	user       string
	site       string
}

// TelegramBotInfo structure contains information about telegram bot
type TelegramBotInfo struct {
	ID        uint64 `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

const telegramTimeOut = 5000 * time.Millisecond
const telegramAPIPrefix = "https://api.telegram.org/bot"
const tgPollInterval = time.Second

// NewTelegram makes telegram bot for notifications
func NewTelegram(params TelegramParams) (*Telegram, error) {
	res := Telegram{TelegramParams: params}

	if res.apiPrefix == "" {
		res.apiPrefix = telegramAPIPrefix
	}
	if res.Timeout == 0 {
		res.Timeout = telegramTimeOut
	}
	res.tgPollInterval = tgPollInterval
	log.Printf("[DEBUG] create new telegram notifier for api=%s, timeout=%s", res.apiPrefix, res.Timeout)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	botInfo, err := res.botInfo(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "can't retrieve bot info from Telegram API")
	}
	res.username = botInfo.Username

	return &res, err
}

// Send to telegram recipients
func (t *Telegram) Send(ctx context.Context, req Request) error {
	log.Printf("[DEBUG] send telegram notification for comment ID %s", req.Comment.ID)
	result := new(multierror.Error)

	msg, err := buildMessage(req)
	if err != nil {
		return errors.Wrapf(err, "failed to make telegram message body for comment ID %s", req.Comment.ID)
	}

	if t.AdminChannelID != "" {
		err := t.sendMessage(ctx, msg, t.AdminChannelID)
		result = multierror.Append(errors.Wrapf(err,
			"problem sending admin telegram notification about comment ID %s to %s", req.Comment.ID, t.AdminChannelID),
		)
	}

	if t.UserNotifications {
		for _, user := range req.Telegrams {
			err := t.sendMessage(ctx, msg, user)
			result = multierror.Append(errors.Wrapf(err,
				"problem sending user telegram notification about comment ID %s to %q", req.Comment.ID, user),
			)
		}
	}
	return result.ErrorOrNil()
}

func (t *Telegram) sendMessage(ctx context.Context, b []byte, chatID string) error {
	if _, err := strconv.ParseInt(chatID, 10, 64); err != nil {
		chatID = "@" + chatID // if chatID not a number enforce @ prefix
	}

	var tgResp = struct {
		OK bool `json:"ok"`
	}{}
	url := fmt.Sprintf("sendMessage?chat_id=%s&disable_web_page_preview=true", chatID)
	return t.request(ctx, url, b, &tgResp)
}

// buildMessage generates message for generic notification about new comment
func buildMessage(req Request) ([]byte, error) {
	commentURLPrefix := req.Comment.Locator.URL + uiNav

	msg := fmt.Sprintf(`<a href="%s">%s</a>`, commentURLPrefix+req.Comment.ID, escapeTelegramText(req.Comment.User.Name))

	if req.Comment.ParentID != "" {
		msg += fmt.Sprintf(" -> <a href=\"%s\">%s</a>", commentURLPrefix+req.parent.ID, escapeTelegramText(req.parent.User.Name))
	}

	msg += fmt.Sprintf("\n\n%s", telegramSupportedHTML(req.Comment.Text))

	if req.Comment.ParentID != "" {
		msg += fmt.Sprintf("\n\n \"_%s_\"", telegramSupportedHTML(req.parent.Text))
	}

	if req.Comment.PostTitle != "" {
		msg += fmt.Sprintf("\n\n↦  <a href=\"%s\">%s</a>", req.Comment.Locator.URL, escapeTelegramText(req.Comment.PostTitle))
	}

	body := telegramMsg{Text: msg, ParseMode: "HTML"}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// returns HTML with only tags allowed in Telegram HTML message payload
// https://core.telegram.org/bots/api#html-style
func telegramSupportedHTML(htmlText string) string {
	p := bluemonday.NewPolicy()
	p.AllowElements("b", "strong", "i", "em", "u", "ins", "s", "strike", "del", "a", "code", "pre")
	p.AllowAttrs("href").OnElements("a")
	p.AllowAttrs("class").OnElements("code")
	return p.Sanitize(htmlText)
}

// returns text sanitized of symbols not allowed inside other HTML tags in Telegram HTML message payload
// https://core.telegram.org/bots/api#html-style
func escapeTelegramText(text string) string {
	// order is important
	text = strings.ReplaceAll(text, "&", "&amp;")
	text = strings.ReplaceAll(text, "<", "&lt;")
	text = strings.ReplaceAll(text, ">", "&gt;")
	return text
}

// SendVerification is not needed for telegram
func (t *Telegram) SendVerification(_ context.Context, _ VerificationRequest) error {
	return nil
}

// TelegramUpdate contains update received from Telegram
type TelegramUpdate struct {
	Result []struct {
		UpdateID int `json:"update_id"`
		Message  struct {
			Chat struct {
				ID   int    `json:"id"`
				Name string `json:"first_name"`
				Type string `json:"type"`
			} `json:"chat"`
			Text string `json:"text"`
		} `json:"message"`
	} `json:"result"`
}

// GetUpdates fetches incoming updates
func (t *Telegram) GetUpdates(ctx context.Context) (*TelegramUpdate, error) {
	url := `getUpdates?allowed_updates=["message"]`
	if t.updateOffset != 0 {
		url += fmt.Sprintf("&offset=%d", t.updateOffset)
	}

	var result TelegramUpdate

	err := t.request(ctx, url, nil, &result)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch updates")
	}

	for _, u := range result.Result {
		if u.UpdateID >= t.updateOffset {
			t.updateOffset = u.UpdateID + 1
		}
	}

	return &result, err
}

// GetBotUsername returns bot username
func (t *Telegram) GetBotUsername() string {
	return t.username
}

// AddToken adds token
func (t *Telegram) AddToken(token, user, site string, expires time.Time) {
	t.requests.Lock()
	t.requests.data[token] = tgAuthRequest{
		expires: expires,
		user:    user,
		site:    site,
	}
	t.requests.Unlock()
}

// CheckToken verifies incoming token, returns the user address if it's confirmed and empty string otherwise
func (t *Telegram) CheckToken(token, user string) (telegram, site string, err error) {
	t.requests.RLock()
	authRequest, ok := t.requests.data[token]
	t.requests.RUnlock()

	if !ok {
		return "", "", errors.New("request is not found")
	}

	if time.Now().After(authRequest.expires) {
		t.requests.Lock()
		delete(t.requests.data, token)
		t.requests.Unlock()
		return "", "", errors.New("request expired")
	}

	if !authRequest.confirmed {
		return "", "", errors.New("request is not verified yet")
	}

	if authRequest.user != user {
		return "", "", errors.New("user does not match original requester")
	}

	// Delete request
	t.requests.Lock()
	delete(t.requests.data, token)
	t.requests.Unlock()

	return authRequest.telegramID, authRequest.site, nil
}

// Run starts processing login requests sent in Telegram, required for user notifications to work
// Blocks caller
func (t *Telegram) Run(ctx context.Context) {
	t.requests.Lock()
	t.requests.data = make(map[string]tgAuthRequest)
	t.requests.Unlock()

	processUpdatedTicker := time.NewTicker(t.tgPollInterval)
	cleanupTicker := time.NewTicker(time.Minute * 5)

	for {
		select {
		case <-ctx.Done():
			processUpdatedTicker.Stop()
			cleanupTicker.Stop()
			return
		case <-processUpdatedTicker.C:
			err := t.processUpdates(ctx)
			if err != nil {
				log.Printf("[WARN] Error while processing telegram updates: %v", err)
			}
		case <-cleanupTicker.C:
			now := time.Now()
			t.requests.Lock()
			for key, req := range t.requests.data {
				if now.After(req.expires) {
					delete(t.requests.data, key)
				}
			}
			t.requests.Unlock()
		}
	}
}

func (t *Telegram) String() string {
	result := "telegram"
	if t.AdminChannelID != "" {
		result += " with admin notifications to " + t.AdminChannelID
	}
	if t.UserNotifications {
		result += " with user notifications enabled"
	}
	return result
}

// processUpdates processes a batch of updates from telegram servers
func (t *Telegram) processUpdates(ctx context.Context) error {
	updates, err := t.GetUpdates(ctx)
	if err != nil {
		return err
	}

	for _, update := range updates.Result {
		if update.Message.Chat.Type != "private" {
			continue
		}

		if !strings.HasPrefix(update.Message.Text, "/start ") {
			err = t.sendText(ctx, update.Message.Chat.ID, t.ErrorMsg)
			if err != nil {
				log.Printf("[WARN] failed to notify telegram peer: %v", err)
			}
			continue
		}

		token := strings.TrimPrefix(update.Message.Text, "/start ")

		t.requests.RLock()
		authRequest, ok := t.requests.data[token]
		if !ok { // No such token
			t.requests.RUnlock()
			err = t.sendText(ctx, update.Message.Chat.ID, t.ErrorMsg)
			if err != nil {
				log.Printf("[WARN] failed to notify telegram peer: %v", err)
			}
			continue
		}
		t.requests.RUnlock()

		authRequest.confirmed = true
		authRequest.telegramID = strconv.Itoa(update.Message.Chat.ID)

		t.requests.Lock()
		t.requests.data[token] = authRequest
		t.requests.Unlock()

		err = t.sendText(ctx, update.Message.Chat.ID, t.SuccessMsg)
		if err != nil {
			log.Printf("[ERROR] failed to notify telegram peer: %v", err)
		}
	}

	return nil
}

// sendText sends a plain text message to telegram peer
func (t *Telegram) sendText(ctx context.Context, recipientID int, msg string) error {
	url := fmt.Sprintf("sendMessage?chat_id=%d&text=%s", recipientID, neturl.PathEscape(msg))
	return t.request(ctx, url, nil, &struct{}{})
}

// botInfo returns info about configured bot
func (t *Telegram) botInfo(ctx context.Context) (*TelegramBotInfo, error) {
	var resp = struct {
		Result *TelegramBotInfo `json:"result"`
	}{}

	err := t.request(ctx, "getMe", nil, &resp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch bot info")
	}

	return resp.Result, nil
}

func (t *Telegram) request(ctx context.Context, method string, b []byte, data interface{}) error {
	return repeater.NewDefault(3, time.Millisecond*250).Do(ctx, func() error {
		url := fmt.Sprintf("%s%s/%s", t.apiPrefix, t.Token, method)

		var req *http.Request
		var err error
		if b == nil {
			req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		} else {
			req, err = http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
		if err != nil {
			return errors.Wrap(err, "failed to create request")
		}

		client := http.Client{Timeout: t.Timeout}
		resp, err := client.Do(req)
		if err != nil {
			return errors.Wrap(err, "failed to send request")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return t.parseError(resp.Body, resp.StatusCode)
		}

		if err = json.NewDecoder(resp.Body).Decode(data); err != nil {
			return errors.Wrap(err, "failed to decode json response")
		}

		return nil
	})
}

func (t *Telegram) parseError(r io.Reader, statusCode int) error {
	tgErr := struct {
		Description string `json:"description"`
	}{}
	if err := json.NewDecoder(r).Decode(&tgErr); err == nil {
		return errors.Errorf("unexpected telegram API status code %d, error: %q", statusCode, tgErr.Description)
	}
	return errors.Errorf("unexpected telegram API status code %d", statusCode)
}
