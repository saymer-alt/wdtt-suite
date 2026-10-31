package main

import (
	"errors"
	"strings"
	"testing"
)

// withBrokenRand подменяет crypto/rand.Read на всегда падающий и
// восстанавливает оригинал по завершении теста.
func withBrokenRand(t *testing.T) {
	t.Helper()
	prev := randRead
	randRead = func(b []byte) (int, error) { return 0, errors.New("synthetic RNG failure") }
	t.Cleanup(func() { randRead = prev })
}

// TestGeneratePasswordFailsClosedOnRNGError: при отказе криптографического
// генератора пароль НЕ выдаётся — ни пустая строка, ни предсказуемый
// fallback (issue #33). Уровень: TEST-PROVEN.
func TestGeneratePasswordFailsClosedOnRNGError(t *testing.T) {
	withBrokenRand(t)
	for i := 0; i < 100; i++ {
		pass, err := generatePassword()
		if err == nil {
			t.Fatalf("iteration %d: expected error on RNG failure, got password %q", i, pass)
		}
		if pass != "" {
			t.Fatalf("iteration %d: fail-closed violated, got password %q", i, pass)
		}
		if !strings.Contains(err.Error(), "crypto/rand") {
			t.Fatalf("iteration %d: error must mention crypto/rand, got %q", i, err.Error())
		}
	}
}

// TestGeneratePasswordNoDeterministicOutput: без подмены два последовательных
// вызова не дают одинаковый пароль (fallback на UnixNano давал бы почти
// совпадающие последовательности).
func TestGeneratePasswordNoDeterministicOutput(t *testing.T) {
	a, err := generatePassword()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := generatePassword()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == b {
		t.Fatalf("two consecutive passwords are identical: %q", a)
	}
}

// TestGeneratePasswordShape: нормальный путь — длина и алфавит сохранены
// (совместимость формата с существующими клиентами).
func TestGeneratePasswordShape(t *testing.T) {
	for i := 0; i < 50; i++ {
		pass, err := generatePassword()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pass) != generatedPasswordLen {
			t.Fatalf("password length %d, want %d", len(pass), generatedPasswordLen)
		}
		for _, c := range pass {
			if !strings.ContainsRune(passChars, c) {
				t.Fatalf("character %q outside passChars alphabet", c)
			}
		}
	}
}
