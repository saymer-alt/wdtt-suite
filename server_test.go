package main

import (
	"errors"
	"strings"
	"testing"
)

// withRNG подменяет точку crypto/rand на время одного теста.
func withRNG(t *testing.T, fake func([]byte) (int, error)) {
	t.Helper()
	orig := randRead
	randRead = fake
	t.Cleanup(func() { randRead = orig })
}

// TestGeneratePasswordFormatAndUniqueness: длина 16, только символы
// алфавита, уникальность на реалистичной партии. Совместимость: ранее
// выданные пароли не затрагиваются — меняется только генерация новых.
func TestGeneratePasswordFormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		pass, err := generatePassword()
		if err != nil {
			t.Fatalf("unexpected RNG error: %v", err)
		}
		if len(pass) != generatedPasswordLen {
			t.Fatalf("len = %d, want %d", len(pass), generatedPasswordLen)
		}
		for _, c := range pass {
			if !strings.ContainsRune(passChars, c) {
				t.Fatalf("char %q outside the allowed alphabet", c)
			}
		}
		if seen[pass] {
			t.Fatalf("duplicate password generated: %q", pass)
		}
		seen[pass] = true
	}
}

// TestGeneratePasswordRNGFailureFailsClosed закрепляет контракт issue #33
// (реализован в #55): при отказе RNG возвращается ("", ошибка) и НИКАКИЙ
// пароль не выдаётся — ни из времени, ни из другой детерминированной
// последовательности.
func TestGeneratePasswordRNGFailureFailsClosed(t *testing.T) {
	withRNG(t, func(b []byte) (int, error) {
		return 0, errors.New("synthetic entropy source failure")
	})
	pass, err := generatePassword()
	if err == nil {
		t.Fatal("expected an error on RNG failure, got nil")
	}
	if pass != "" {
		t.Fatalf("no credential may be issued on RNG failure, got %q", pass)
	}
}

// TestGeneratePasswordRejectsBiasedBytes доказывает rejection sampling:
// байты >= 256-(256%len(passChars)) отбрасываются, принятые значения
// отображаются в алфавит, длина вывода остаётся ровно
// generatedPasswordLen.
func TestGeneratePasswordRejectsBiasedBytes(t *testing.T) {
	max := 256 - (256 % len(passChars))
	if max != 220 { // алфавит 55 символов: 256 % 55 == 36
		t.Fatalf("alphabet %d: expected rejection threshold 220, got %d", len(passChars), max)
	}
	pattern := []byte{255, 0, 230, 219, 229, 1, 220, 2}
	pos := 0
	withRNG(t, func(b []byte) (int, error) {
		for i := range b {
			b[i] = pattern[pos%len(pattern)]
			pos++
		}
		return len(b), nil
	})
	pass, err := generatePassword()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pass) != generatedPasswordLen {
		t.Fatalf("len = %d, want %d", len(pass), generatedPasswordLen)
	}
	// В алфавит могут попасть только значения < max. Принятые значения
	// в шаблоне: 0,1,2 (индексы 0..2) и 219 (219 % 55 == 54).
	allowed := map[byte]bool{passChars[0]: true, passChars[1]: true,
		passChars[2]: true, passChars[54]: true}
	for i := 0; i < len(pass); i++ {
		if !allowed[pass[i]] {
			t.Fatalf("position %d char %q was produced by a biased/rejected byte", i, pass[i])
		}
	}
}

// TestGeneratePasswordCoverage: с настоящим источником энтропии весь
// алфавит достигается на реалистичной партии (санити, не доказательство
// равномерности).
func TestGeneratePasswordCoverage(t *testing.T) {
	seen := make(map[rune]bool, len(passChars))
	for i := 0; i < 100; i++ {
		pass, err := generatePassword()
		if err != nil {
			t.Fatalf("unexpected RNG error: %v", err)
		}
		for _, c := range pass {
			seen[c] = true
		}
	}
	if len(seen) < len(passChars) {
		t.Fatalf("only %d of %d alphabet chars observed in 1600 draws", len(seen), len(passChars))
	}
}
