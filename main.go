package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Discord color values
const (
	ColorRed       = 0xd00000
	ColorGreen     = 0x36A64F
	ColorGrey      = 0x95A5A6
	AlertNameLabel = "alertname"
)

type AlertManagerData struct {
	Receiver string             `json:"receiver"`
	Status   string             `json:"status"`
	Alerts   AlertManagerAlerts `json:"alerts"`

	GroupLabels       KV `json:"groupLabels"`
	CommonLabels      KV `json:"commonLabels"`
	CommonAnnotations KV `json:"commonAnnotations"`

	ExternalURL string `json:"externalURL"`
	GroupKey    string `json:"groupKey"`
	Version     string `json:"version"`
}

type AlertManagerAlert struct {
	Status       string    `json:"status"`
	Labels       KV        `json:"labels"`
	Annotations  KV        `json:"annotations"`
	StartsAt     time.Time `json:"startsAt"`
	EndsAt       time.Time `json:"endsAt"`
	GeneratorURL string    `json:"generatorURL"`
	Fingerprint  string    `json:"fingerprint"`
}

// KV is a set of key/value string pairs.
type KV map[string]string

// Pair is a key/value string pair.
type Pair struct {
	Name, Value string
}

// Pairs is a list of key/value string pairs.
type Pairs []Pair

// SortedPairs returns a sorted list of key/value pairs.
func (kv KV) SortedPairs() Pairs {
	var (
		pairs     = make([]Pair, 0, len(kv))
		keys      = make([]string, 0, len(kv))
		sortStart = 0
	)
	for k := range kv {
		if k == AlertNameLabel {
			keys = append([]string{k}, keys...)
			sortStart = 1
		} else {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys[sortStart:])

	for _, k := range keys {
		pairs = append(pairs, Pair{k, kv[k]})
	}
	return pairs
}

// Alerts is a list of Alert objects.
type AlertManagerAlerts []AlertManagerAlert

type DiscordEmbedFooter struct {
	Text string `json:"text"`
}

type DiscordMessage struct {
	Content   string        `json:"content"`
	Username  string        `json:"username"`
	AvatarURL string        `json:"avatar_url"`
	Embeds    DiscordEmbeds `json:"embeds"`
}

type DiscordEmbeds []DiscordEmbed

type DiscordEmbed struct {
	Title       string              `json:"title,omitempty"`
	Description string              `json:"description,omitempty"`
	URL         string              `json:"url,omitempty"`
	Color       int                 `json:"color,omitempty"`
	Fields      DiscordEmbedFields  `json:"fields,omitempty"`
	Footer      *DiscordEmbedFooter `json:"footer,omitempty"`
	Timestamp   *time.Time          `json:"timestamp,omitempty"`
}

type DiscordEmbedFields []DiscordEmbedField

type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

const defaultListenAddress = "127.0.0.1:9094"
const discordEmbedLimit = 10

var (
	webhookURL               = flag.String("webhook.url", os.Getenv("DISCORD_WEBHOOK"), "Discord WebHook URL.")
	additionalWebhookURLFlag = flag.String("additionalWebhook.urls", os.Getenv("ADDITIONAL_DISCORD_WEBHOOKS"), "Additional Discord WebHook URLs.")
	listenAddress            = flag.String("listen.address", os.Getenv("LISTEN_ADDRESS"), "Address:Port to listen on.")
	username                 = flag.String("username", os.Getenv("DISCORD_USERNAME"), "Overrides the predefined username of the webhook.")
	avatarURL                = flag.String("avatar.url", os.Getenv("DISCORD_AVATAR_URL"), "Overrides the predefined avatar of the webhook.")
	verboseMode              = flag.String("verbose", os.Getenv("VERBOSE"), "Verbose mode")
	additionalWebhookURLs    []string
)

func checkWebhookURL(webhookURL string) bool {
	if webhookURL == "" {
		log.Fatalf("Environment variable 'DISCORD_WEBHOOK' or CLI parameter 'webhook.url' not found.")
		return false
	}
	_, err := url.Parse(webhookURL)
	if err != nil {
		log.Fatalf("The Discord WebHook URL doesn't seem to be a valid URL.")
		return false
	}

	re := regexp.MustCompile(`https://discord(?:app)?.com/api/webhooks/[0-9]{18,19}/[a-zA-Z0-9_-]+`)
	if ok := re.Match([]byte(webhookURL)); !ok {
		log.Printf("The Discord WebHook URL doesn't seem to be valid.")
		return false
	}
	return true
}
func checkDiscordUserName(discordUserName string) {
	if discordUserName == "" {
		log.Fatalf("Environment variable 'DISCORD_USERNAME' or CLI parameter 'username' not found.")
	}
	_, err := url.Parse(discordUserName)
	if err != nil {
		log.Fatalf("The Discord UserName doesn't seem to be a valid.")
	}
}

func sendWebhook(alertManagerData *AlertManagerData) {

	groupedAlerts := make(map[string]AlertManagerAlerts)

	for _, alert := range alertManagerData.Alerts {
		groupedAlerts[alert.Status] = append(groupedAlerts[alert.Status], alert)
	}

	for status, alerts := range groupedAlerts {

		color := findColor(status)

		embeds := DiscordEmbeds{}

		for indx, alert := range alerts {
			embedAlertMessage := DiscordEmbed{
				Title:  getAlertTitle(&alert),
				Color:  color,
				Fields: DiscordEmbedFields{},
			}

			if alert.Annotations["message"] != "" {
				embedAlertMessage.Fields = append(embedAlertMessage.Fields, DiscordEmbedField{
					Name:  "*Message:*",
					Value: alert.Annotations["message"],
				})
			}

			if alert.Annotations["description"] != "" {
				embedAlertMessage.Fields = append(embedAlertMessage.Fields, DiscordEmbedField{
					Name:  "*Description:*",
					Value: alert.Annotations["description"],
				})
			}

			embedAlertMessage.Fields = append(embedAlertMessage.Fields, DiscordEmbedField{
				Name:  "*Details:*",
				Value: getFormattedLabels(alert.Labels),
			})

			// Include the alert status (firing/resolved) so it's always visible in the embed
			embedAlertMessage.Fields = append(embedAlertMessage.Fields, DiscordEmbedField{
				Name:   "*Status:*",
				Value:  fmt.Sprintf("`%s`", alert.Status),
				Inline: true,
			})

			if *username != "" {
				footer := DiscordEmbedFooter{}
				footer.Text = *username
				embedAlertMessage.Footer = &footer
				currentTime := time.Now()
				embedAlertMessage.Timestamp = &currentTime
			}
			embeds = append(embeds, embedAlertMessage)

			//Check if number of embeds are greater than discord limit and push to discord
			if (indx+1)%(discordEmbedLimit-1) == 0 {
				log.Printf("Sending chunk of data to discord")
				postMessageToDiscord(alertManagerData, status, color, embeds)
				embeds = DiscordEmbeds{}
			}
		}

		if len(embeds) > 0 {
			log.Printf("Sending last chunk of data to discord")
			postMessageToDiscord(alertManagerData, status, color, embeds)
		}
	}
}

func postMessageToDiscord(alertManagerData *AlertManagerData, status string, color int, embeds DiscordEmbeds) {
	discordMessage := buildDiscordMessage(alertManagerData, status, len(embeds), color)
	discordMessage.Embeds = append(discordMessage.Embeds, embeds...)
	// Enforce Discord limits and sanitize content to avoid API rejections
	discordMessage.Embeds = sanitizeEmbeds(discordMessage.Embeds)
	discordMessageBytes, _ := json.Marshal(discordMessage)
	if *verboseMode == "ON" || *verboseMode == "true" {
		log.Printf("Sending webhook message to Discord: %s", string(discordMessageBytes))
	}
	// Send to primary webhook
	if err := sendToWebhook(*webhookURL, discordMessageBytes); err != nil {
		log.Printf("error sending to primary webhook: %v", err)
	}
	// Send to additional webhooks
	for _, webhook := range additionalWebhookURLs {
		if err := sendToWebhook(webhook, discordMessageBytes); err != nil {
			log.Printf("error sending to additional webhook %s: %v", webhook, err)
		}
	}
}

func sendToWebhook(webHook string, discordMessageBytes []byte) error {
	response, err := http.Post(webHook, "application/json", bytes.NewReader(discordMessageBytes))
	if err != nil {
		return fmt.Errorf("failed to POST to webhook %s: %w", webHook, err)
	}
	defer response.Body.Close()

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Collect useful headers for diagnostics
	headers := map[string]string{
		"Retry-After":             response.Header.Get("Retry-After"),
		"X-RateLimit-Limit":       response.Header.Get("X-RateLimit-Limit"),
		"X-RateLimit-Remaining":   response.Header.Get("X-RateLimit-Remaining"),
		"X-RateLimit-Reset":       response.Header.Get("X-RateLimit-Reset"),
		"X-RateLimit-Reset-After": response.Header.Get("X-RateLimit-Reset-After"),
		"X-Discord-Request-Id":    response.Header.Get("X-Discord-Request-Id"),
	}
	headerParts := make([]string, 0, len(headers))
	for k, v := range headers {
		if v != "" {
			headerParts = append(headerParts, fmt.Sprintf("%s=%s", k, v))
		}
	}
	headerInfo := ""
	if len(headerParts) > 0 {
		headerInfo = " (" + strings.Join(headerParts, ", ") + ")"
	}

	// Try to parse JSON error body
	var discordErr map[string]interface{}
	if err := json.Unmarshal(responseData, &discordErr); err == nil {
		msg := ""
		if m, ok := discordErr["message"].(string); ok && m != "" {
			msg = m
		}
		if e, ok := discordErr["errors"]; ok {
			log.Printf("Webhook message to Discord failed (%d)%s: %s - errors: %v - raw: %s", response.StatusCode, headerInfo, msg, e, truncateString(string(responseData), 1024))
		} else if msg != "" {
			log.Printf("Webhook message to Discord failed (%d)%s: %s - raw: %s", response.StatusCode, headerInfo, msg, truncateString(string(responseData), 1024))
		} else {
			log.Printf("Webhook message to Discord failed (%d)%s: parsed JSON but no message/errors - raw: %s", response.StatusCode, headerInfo, truncateString(string(responseData), 1024))
		}
	} else {
		if len(responseData) == 0 {
			log.Printf("Webhook message to Discord failed (%d)%s: empty response body", response.StatusCode, headerInfo)
		} else {
			log.Printf("Webhook message to Discord failed (%d)%s: %s", response.StatusCode, headerInfo, truncateString(string(responseData), 1024))
		}
	}
	return fmt.Errorf("discord webhook returned status %d", response.StatusCode)
}

func buildDiscordMessage(alertManagerData *AlertManagerData, status string, numberOfAlerts int, color int) DiscordMessage {
	discordMessage := DiscordMessage{}
	addOverrideFields(&discordMessage)
	messageHeader := DiscordEmbed{
		Title:  fmt.Sprintf("[%s:%d] %s", strings.ToUpper(status), numberOfAlerts, getAlertName(alertManagerData)),
		URL:    alertManagerData.ExternalURL,
		Color:  color,
		Fields: DiscordEmbedFields{},
	}
	discordMessage.Embeds = DiscordEmbeds{messageHeader}
	return discordMessage
}

// Discord limits (see docs): title <= 256, description <= 4096, fields <= 25, field name <= 256, field value <= 1024, embeds <= 10
func sanitizeEmbeds(embeds DiscordEmbeds) DiscordEmbeds {
	const (
		maxEmbeds      = 10
		maxFields      = 25
		maxTitleLen    = 256
		maxDescLen     = 4096
		maxFieldName   = 256
		maxFieldValue  = 1024
	)
	if len(embeds) > maxEmbeds {
		log.Printf("sanitizing embeds: trimming %d embeds to Discord max %d", len(embeds)-maxEmbeds, maxEmbeds)
		embeds = embeds[:maxEmbeds]
	}
	for i := range embeds {
		// Title
		if len(embeds[i].Title) > maxTitleLen {
			log.Printf("sanitizing embed %d title (len=%d) to %d chars", i, len(embeds[i].Title), maxTitleLen)
			embeds[i].Title = truncateString(embeds[i].Title, maxTitleLen)
		}
		// Description
		if len(embeds[i].Description) > maxDescLen {
			log.Printf("sanitizing embed %d description (len=%d) to %d chars", i, len(embeds[i].Description), maxDescLen)
			embeds[i].Description = truncateString(embeds[i].Description, maxDescLen)
		}
		// Fields
		if len(embeds[i].Fields) > maxFields {
			log.Printf("sanitizing embed %d fields: trimming %d fields to %d", i, len(embeds[i].Fields)-maxFields, maxFields)
			embeds[i].Fields = embeds[i].Fields[:maxFields]
		}
		for j := range embeds[i].Fields {
			if len(embeds[i].Fields[j].Name) > maxFieldName {
				embeds[i].Fields[j].Name = truncateString(embeds[i].Fields[j].Name, maxFieldName)
			}
			if len(embeds[i].Fields[j].Value) > maxFieldValue {
				embeds[i].Fields[j].Value = truncateString(embeds[i].Fields[j].Value, maxFieldValue)
			}
		}
		// Validate URL scheme - Discord accepts http/https. If invalid, clear it.
		if embeds[i].URL != "" {
			if !isValidHTTPURL(embeds[i].URL) {
				log.Printf("sanitizing embed %d URL (invalid scheme or format): %s", i, embeds[i].URL)
				embeds[i].URL = ""
			}
		}
	}
	return embeds
}

// isValidHTTPURL returns true if the URL parses and uses http or https scheme
func isValidHTTPURL(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "http" || scheme == "https"
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}



func addOverrideFields(discordMessage *DiscordMessage) {
	if *username != "" {
		discordMessage.Username = *username
	}
	if *avatarURL != "" {
		discordMessage.AvatarURL = *avatarURL
	}
}

func getFormattedLabels(labels KV) string {
	var builder strings.Builder
	for _, pair := range labels.SortedPairs() {
		builder.WriteString(fmt.Sprintf("• *%s:* `%s`\n", pair.Name, pair.Value))
	}
	if builder.Len() == 0 {
		builder.WriteString("-")
	}
	return builder.String()
}

func getAlertTitle(alertManagerAlert *AlertManagerAlert) string {
	var builder strings.Builder
	builder.WriteString("*Alert:* ")
	builder.WriteString(alertManagerAlert.Annotations["summary"])
	if alertManagerAlert.Labels["severity"] != "" {
		builder.WriteString(" - ")
		builder.WriteString(fmt.Sprintf("`%s`", alertManagerAlert.Labels["severity"]))
	}
	return builder.String()
}

func findColor(status string) int {
	color := ColorGrey
	if status == "firing" {
		color = ColorRed
	} else if status == "resolved" {
		color = ColorGreen
	}
	return color
}

func isNotBlankOrEmpty(str string) bool {
	re := regexp.MustCompile(`\S+`)
	return re.MatchString(str)
}

func getAlertName(alertManagerData *AlertManagerData) string {
	icon := ""
	if alertManagerData.Status == "firing" {
		if alertManagerData.CommonLabels["severity"] == "critical" {
			icon = "🔥 "
		} else if alertManagerData.CommonLabels["severity"] == "warning" {
			icon = "⚠️ "
		} else {
			icon = "ℹ️ "
		}
	} else {
		icon = "💚 "
	}

	if alertManagerData.CommonAnnotations["summary"] != "" {
		return icon + alertManagerData.CommonAnnotations["summary"]
	}
	if alertManagerData.CommonAnnotations["message"] != "" {
		return icon + alertManagerData.CommonAnnotations["message"]
	}
	if alertManagerData.CommonAnnotations["description"] != "" {
		return icon + alertManagerData.CommonAnnotations["description"]
	}
	return icon + alertManagerData.CommonLabels["alertname"]
}

func sendRawPromAlertWarn() {
	badString := `This program is suppose to be fed by alert manager.` + "\n" +
		`It is not a replacement for alert manager, it is a ` + "\n" +
		`webhook target for it. Please read the README.md  ` + "\n" +
		`for guidance on how to configure it for alertmanager` + "\n" +
		`or https://prometheus.io/docs/alerting/latest/configuration/#webhook_config`

	log.Print(`/!\ -- You have misconfigured this program -- /!\`)
	log.Print(`--- --                                      -- ---`)
	log.Print(badString)

	discordMessage := DiscordMessage{
		Content: "",
		Embeds: DiscordEmbeds{
			{
				Title:       "misconfigured program",
				Description: badString,
				Color:       ColorGrey,
				Fields:      DiscordEmbedFields{},
			},
		},
	}

	discordMessageBytes, _ := json.Marshal(discordMessage)
	http.Post(*webhookURL, "application/json", bytes.NewReader(discordMessageBytes))
}

func main() {
	flag.Parse()
	// Check required webhook URL
	checkWebhookURL(*webhookURL)
	// Validate and collect additional webhooks
	for _, additionalWebhook := range strings.Split(*additionalWebhookURLFlag, ",") {
		if isNotBlankOrEmpty(additionalWebhook) && checkWebhookURL(additionalWebhook) {
			additionalWebhookURLs = append(additionalWebhookURLs, additionalWebhook)
		}
	}
	// Username is optional - warn if missing, truncate if too long
	if *username == "" {
		log.Printf("No Discord username override set; webhook default will be used")
	} else {
		if len(*username) > 80 {
			log.Printf("Discord username override is too long; truncating to 80 chars")
			*username = truncateString(*username, 80)
		}
	}
	// Avatar URL is optional - validate scheme if provided
	if *avatarURL != "" {
		if !isValidHTTPURL(*avatarURL) {
			log.Printf("Discord avatar URL appears invalid; ignoring: %s", *avatarURL)
			*avatarURL = ""
		}
	}

	checkDiscordUserName(*username)

	if *listenAddress == "" {
		*listenAddress = defaultListenAddress
	}

	log.Printf("Listening on: %s", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, http.HandlerFunc(handleWebHook)))
}

func handleWebHook(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s - [%s] %s", r.Host, r.Method, r.URL.RawPath)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	if *verboseMode == "ON" {
		log.Printf("request payload: %s", string(body))
	}

	alertManagerData := AlertManagerData{}
	err = json.Unmarshal(body, &alertManagerData)
	if err != nil {
		if isRawPromAlert(body) {
			sendRawPromAlertWarn()
			return
		}
		if len(body) > 1024 {
			log.Printf("Failed to unpack inbound alert request - %s...", string(body[:1023]))

		} else {
			log.Printf("Failed to unpack inbound alert request - %s", string(body))
		}
		return
	}
	sendWebhook(&alertManagerData)
}
