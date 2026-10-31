package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"
)

// Канареечные значения строго фиктивные: реальные креды/токены/ссылки в
// тестах не используются и не требуются.
const (
	canaryCreds    = "CANARY-turn-creds-Qz1wYXNzd29yZA=="
	canaryCaptcha  = "CANARY-captcha-token-03AGdBq2x"
	canaryUnknown  = "CANARY-unknown-secret-9f8e7d6c"
	canaryLink     = "CANARY-private-vk-call-link-7c1f2b"
	canaryUser     = "CANARY-turn-user"
	canaryPass     = "CANARY-turn-pass"
	canaryTurnURL  = "turn:CANARY-turn-host:3478"
	receiveTimeout = 2 * time.Second
)

func assertNoLeak(t *testing.T, name, safe, canary string, ok bool, wantOK bool) {
	t.Helper()
	if ok != wantOK {
		t.Fatalf("%s: loggable=%v, want %v", name, ok, wantOK)
	}
	if strings.Contains(safe, canary) {
		t.Fatalf("%s: canary leaked into log representation: %q", name, safe)
	}
}

func captureStdLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	fn()
	return buf.String()
}

func TestRedactStdinSensitiveCommands(t *testing.T) {
	safe, ok := redactStdinForLog("TURN_CREDS|" + canaryCreds)
	assertNoLeak(t, "TURN_CREDS", safe, canaryCreds, ok, true)
	if !strings.HasPrefix(safe, "TURN_CREDS|") {
		t.Fatalf("TURN_CREDS command name lost: %q", safe)
	}
	if !strings.Contains(safe, "<redacted>") {
		t.Fatalf("TURN_CREDS payload not marked redacted: %q", safe)
	}

	safe, ok = redactStdinForLog("CAPTCHA_RESULT|" + canaryCaptcha)
	assertNoLeak(t, "CAPTCHA_RESULT", safe, canaryCaptcha, ok, true)
	if !strings.Contains(safe, "<redacted>") {
		t.Fatalf("CAPTCHA_RESULT payload not marked redacted: %q", safe)
	}
}

func TestRedactStdinControlCommandsVisible(t *testing.T) {
	for _, cmd := range []string{"PAUSE", "RESUME", "STOP"} {
		safe, ok := redactStdinForLog(cmd)
		if !ok || safe != cmd {
			t.Fatalf("%s must stay visible by name, got %q ok=%v", cmd, safe, ok)
		}
	}
}

func TestRedactStdinUnknownNeverLogged(t *testing.T) {
	safe, ok := redactStdinForLog("SOME_NEW_COMMAND|" + canaryUnknown)
	assertNoLeak(t, "unknown command", safe, canaryUnknown, ok, false)
	if safe != "" {
		t.Fatalf("unknown command must not produce log text, got %q", safe)
	}

	safe, ok = redactStdinForLog("")
	assertNoLeak(t, "empty line", safe, canaryUnknown, ok, false)
}

// TestRedactStdinLongAndCorruptInput проверяет классификатор на больших и
// повреждённых входных данных. Отдельно отметим: реальный STDIN-loop
// ограничен буфером bufio.Scanner (~64KiB на строку) — этот лимит здесь не
// меняется; тест ниже использует payload заметно меньше лимита.
func TestRedactStdinLongAndCorruptInput(t *testing.T) {
	long := strings.Repeat("A|"+canaryCreds, 2000) // ~44 KiB payload
	safe, ok := redactStdinForLog("TURN_CREDS|" + long)
	assertNoLeak(t, "long TURN_CREDS", safe, canaryCreds, ok, true)
	if len(safe) > 64 {
		t.Fatalf("redacted representation must be short, got %d bytes", len(safe))
	}

	corrupt := "TURN_CREDS|\x00\xff\xfe broken \x80 utf8 " + canaryCreds
	safe, ok = redactStdinForLog(corrupt)
	assertNoLeak(t, "corrupt TURN_CREDS", safe, canaryCreds, ok, true)

	corruptUnknown := strings.Repeat("\xff\x00", 1024) + canaryUnknown
	safe, ok = redactStdinForLog(corruptUnknown)
	assertNoLeak(t, "corrupt unknown", safe, canaryUnknown, ok, false)
}

// TestStdinLogLineFiltersErrorMarker проверяет предварительный фильтр
// STDIN-loop (stdinLogLine), а не только классификатор: строки с
// "error:tunnel stopped" не попадают в журнал даже с чувствительным
// префиксом и содержимым.
func TestStdinLogLineFiltersErrorMarker(t *testing.T) {
	line := "TURN_CREDS|error:tunnel stopped|" + canaryCreds
	safe, ok := stdinLogLine(line)
	if ok {
		t.Fatalf("error-marker line must be suppressed, got %q", safe)
	}
	if strings.Contains(safe, canaryCreds) {
		t.Fatalf("canary leaked from suppressed line: %q", safe)
	}

	safe, ok = stdinLogLine("PAUSE")
	if !ok || safe != "PAUSE" {
		t.Fatalf("normal command must pass through, got %q ok=%v", safe, ok)
	}
}

// TestShortLinkWithholdsContent: shortLink не должен выводить ни весь
// приватный link, ни его префикс — только безопасную сводку (длину).
func TestShortLinkWithholdsContent(t *testing.T) {
	for name, link := range map[string]string{
		"short": "c1",        // <= 8 байт: раньше возвращался целиком
		"edge":  "CANARYabc", // ровно 9 байт: раньше срезались первые 8
		"long":  canaryLink,  // длинная фиктивная приватная ссылка
	} {
		got := shortLink(link)
		if strings.Contains(got, link) {
			t.Fatalf("%s: full link leaked: %q", name, got)
		}
		if len(link) > 8 && strings.Contains(got, link[:8]) {
			t.Fatalf("%s: link prefix leaked: %q", name, got)
		}
		if !strings.Contains(got, "<withheld:") {
			t.Fatalf("%s: expected withheld marker, got %q", name, got)
		}
	}
}

// TestVkAccountCredsLogsRedacted покрывает обе ветки handleTurnCredsStdin
// (принято/отклонено) с фиктивной приватной ссылкой и кредами: журнал не
// должен содержать link/логин/пароль, внутренняя авторизация сохраняется.
func TestVkAccountCredsLogsRedacted(t *testing.T) {
	drainTurnCredsResult()

	payload := turnCredsPayload{User: canaryUser, Pass: canaryPass, URLs: []string{canaryTurnURL}}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	line := "TURN_CREDS|" + canaryLink + "|" + base64.StdEncoding.EncodeToString(raw)

	var logText string
	var got turnCredsPayload
	logText = captureStdLog(t, func() {
		handleTurnCredsStdinLine(line)
		select {
		case got = <-TurnCredsResultChan:
		case <-time.After(receiveTimeout):
			t.Fatal("accepted payload not delivered to channel")
		}
	})

	if !strings.Contains(logText, "received") {
		t.Fatalf("accepted branch not logged: %q", logText)
	}
	for name, canary := range map[string]string{"link": canaryLink, "user": canaryUser, "pass": canaryPass, "url": canaryTurnURL} {
		if strings.Contains(logText, canary) {
			t.Fatalf("accepted branch leaked %s into log: %q", name, logText)
		}
	}
	// Внутренняя авторизация: link и креды сохранены для lookup/IPC.
	if got.User != canaryUser || got.Pass != canaryPass || len(got.URLs) == 0 {
		t.Fatalf("channel payload lost credentials: %+v", got)
	}
	if _, _, _, ok := getInjectedTurnCreds(canaryLink); !ok {
		t.Fatalf("injected creds not reachable by original link")
	}
}

func TestVkAccountCredsRejectedLogRedacted(t *testing.T) {
	drainTurnCredsResult()

	payload := turnCredsPayload{User: "", Pass: canaryPass, URLs: []string{canaryTurnURL}}
	raw, _ := json.Marshal(payload)
	line := "TURN_CREDS|" + canaryLink + "|" + base64.StdEncoding.EncodeToString(raw)

	logText := captureStdLog(t, func() {
		handleTurnCredsStdinLine(line)
	})
	if !strings.Contains(logText, "rejected") {
		t.Fatalf("rejected branch not logged: %q", logText)
	}
	if strings.Contains(logText, canaryLink) || strings.Contains(logText, canaryPass) {
		t.Fatalf("rejected branch leaked link or credentials: %q", logText)
	}
}
