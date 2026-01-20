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
	// If DUMP_ENVS_FULL is set, print the webhook URL(s) and full payload for debugging
	dumpFull := os.Getenv("DUMP_ENVS_FULL") == "true" || os.Getenv("DUMP_ENVS_FULL") == "1"
	if dumpFull {
		log.Printf("Posting to primary webhook: %s", *webhookURL)
		log.Printf("Payload: %s", string(discordMessageBytes))
	}
	sendToWebhook(*webhookURL, discordMessageBytes)
	for _, webhook := range additionalWebhookURLs {
		if dumpFull {
			log.Printf("Posting to additional webhook: %s", webhook)
			log.Printf("Payload: %s", string(discordMessageBytes))
		}
		sendToWebhook(webhook, discordMessageBytes)
	}
}

func sendToWebhook(webHook string, discordMessageBytes []byte) {
	// If DUMP_ENVS_FULL is set, print the webhook URL and payload before sending
	dumpFull := os.Getenv("DUMP_ENVS_FULL") == "true" || os.Getenv("DUMP_ENVS_FULL") == "1"
	if dumpFull {
		log.Printf("POSTing to webhook: %s", webHook)
		log.Printf("Payload: %s", string(discordMessageBytes))
	}

	response, err := http.Post(webHook, "application/json", bytes.NewReader(discordMessageBytes))
	if err != nil {
		log.Printf("failed to POST to webhook: %v", err)
		return
	}
	defer response.Body.Close()

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return
	}

	responseData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf("failed to read response body: %v", err)
		return
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
		if len(embeds[i].Title) > maxTitleLen {
			log.Printf("sanitizing embed %d title (len=%d) to %d chars", i, len(embeds[i].Title), maxTitleLen)
			embeds[i].Title = truncateString(embeds[i].Title, maxTitleLen)
		}
		if len(embeds[i].Description) > maxDescLen {
			log.Printf("sanitizing embed %d description (len=%d) to %d chars", i, len(embeds[i].Description), maxDescLen)
			embeds[i].Description = truncateString(embeds[i].Description, maxDescLen)
		}
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
	}
	return embeds
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

// sensitiveEnv returns true if the env var name looks sensitive and should be redacted
func sensitiveEnv(name string) bool {
	name = strings.ToUpper(name)
	sensitiveKeywords := []string{"TOKEN", "KEY", "SECRET", "PASSWORD", "PASS", "WEBHOOK"}
	for _, k := range sensitiveKeywords {
		if strings.Contains(name, k) {
			return true
		}
	}
	return false
}

// logEnvVars logs all environment variables. Sensitive values are redacted by default.
// To see full values, set DUMP_ENVS_FULL=true in the environment (use with caution).
func logEnvVars() {
	envs := os.Environ()
	full := os.Getenv("DUMP_ENVS_FULL") == "true" || os.Getenv("DUMP_ENVS_FULL") == "1"
	log.Printf("Environment variables (sensitive values redacted; set DUMP_ENVS_FULL=true to show full values). Count: %d", len(envs))
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		k := parts[0]
		v := ""
		if len(parts) > 1 {
			v = parts[1]
		}
		if full || !sensitiveEnv(k) {
			log.Printf("ENV %s=%s", k, v)
		} else {
			red := fmt.Sprintf("<redacted len=%d prefix=%s>", len(v), truncateString(v, 4))
			log.Printf("ENV %s=%s", k, red)
		}
	}
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
	// Log environment variables for debugging. Sensitive values are redacted unless DUMP_ENVS_FULL=true
	logEnvVars()
	checkWebhookURL(*webhookURL)
	for _, additionalWebhook := range strings.Split(*additionalWebhookURLFlag, ",") {
		if isNotBlankOrEmpty(additionalWebhook) && checkWebhookURL(additionalWebhook) {
			additionalWebhookURLs = append(additionalWebhookURLs, additionalWebhook)
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
