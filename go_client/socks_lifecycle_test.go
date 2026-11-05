package main

// Сквозной лайфсайкл-тест SOCKS5-тракта go_client (issue #52, методика KB #28):
//
//	реальный userspace WireGuard — два устройства поверх UDP 127.0.0.1,
//	эхо-сервер внутри netstack устройства A,
//	продакшн-код runSocks5Server + startUserspaceWireGuard без единой правки,
//	SOCKS5-клиент на настоящем TCP 127.0.0.1.
//
// Проверяются:
//  1. целостность данных: SHA-256 известного payload туда-обратно (KB #28);
//  2. выживание сервера после резких обрывов сессий в середине передачи;
//  3. чистое завершение по отмене контекста: runSocks5Server возвращает nil,
//     слушатель реально закрыт;
//  4. отсутствие утечек goroutine/файловых дескрипторов после серии сессий.
//
// Всё локально и детерминированно: ни DNS, ни внешней сети, ни реальных ключей.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func x25519Pair(t *testing.T) (privB64, privHex, pubHex, pubB64 string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := k.PublicKey().Bytes()
	return base64.StdEncoding.EncodeToString(k.Bytes()),
		hex.EncodeToString(k.Bytes()),
		hex.EncodeToString(pub),
		base64.StdEncoding.EncodeToString(pub)
}

// freePort резервирует ephemeral-порт и сразу его освобождает: окно гонки
// минимально, а занятость порта поверх слушателя дала бы явную ошибку.
// Замечание: общий net.Listen("udp", ...) в некоторых окружениях (WSL)
// даёт "unexpected address type", поэтому для udp берём ListenUDP напрямую.
func freePort(t *testing.T, network string) int {
	t.Helper()
	switch network {
	case "udp":
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("free port (udp): %v", err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	default:
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			t.Fatalf("free port (%s): %v", network, err)
		}
		defer ln.Close()
		return ln.Addr().(*net.TCPAddr).Port
	}
}

// startEchoDevice поднимает устройство A: netstack 10.0.0.1 с эхо-сервером
// на 10.0.0.1:7777 и peer'ом B (allowed_ip 10.0.0.2/32). Возвращает
// устройство и фактический UDP-порт B (для endpoint'а в конфиге B).
func startEchoDevice(t *testing.T, aPrivHex, bPubHex string) (*device.Device, int) {
	t.Helper()
	for attempt := 0; ; attempt++ {
		udpA := freePort(t, "udp")
		tunA, netA, err := netstack.CreateNetTUN(
			[]netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil, 1280)
		if err != nil {
			t.Fatalf("CreateNetTUN(A): %v", err)
		}
		devA := device.NewDevice(tunA, conn.NewDefaultBind(),
			device.NewLogger(device.LogLevelError, "[wg-a-test] "))
		ipcA := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.0.0.2/32\n",
			aPrivHex, udpA, bPubHex)
		if err := devA.IpcSet(ipcA); err != nil {
			devA.Close()
			if attempt >= 2 {
				t.Fatalf("IpcSet(A): %v", err)
			}
			continue // порт мог занять сосед по машине — берём другой
		}
		if err := devA.Up(); err != nil {
			devA.Close()
			t.Fatalf("devA.Up: %v", err)
		}
		echoAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 7777}
		ln, err := netA.ListenTCP(echoAddr)
		if err != nil {
			devA.Close()
			t.Fatalf("echo listen: %v", err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					io.Copy(c, c)
					c.Close()
				}(c)
			}
		}()
		t.Cleanup(devA.Close)
		return devA, udpA
	}
}

// socks5Connect выполняет рукопожатие SOCKS5 CONNECT на IPv4-литерал.
func socks5Connect(t *testing.T, proxyAddr string, dstIP net.IP, dstPort uint16) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		c.Close()
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		c.Close()
		t.Fatalf("greeting write: %v", err)
	}
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil {
		c.Close()
		t.Fatalf("greeting read: %v", err)
	}
	if greet[0] != 5 || greet[1] != 0 {
		c.Close()
		t.Fatalf("greeting reply: %#v", greet)
	}
	req := []byte{5, 1, 0, 1}
	req = append(req, dstIP.To4()...)
	var portb [2]byte
	binary.BigEndian.PutUint16(portb[:], dstPort)
	req = append(req, portb[:]...)
	if _, err := c.Write(req); err != nil {
		c.Close()
		t.Fatalf("connect write: %v", err)
	}
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		c.Close()
		t.Fatalf("connect reply head: %v", err)
	}
	if head[0] != 5 || head[1] != 0 {
		c.Close()
		t.Fatalf("connect reply: ver=%d rep=%d (ожидали success)", head[0], head[1])
	}
	switch head[3] {
	case 1: // IPv4: ещё 4+2 байта
		var rest [6]byte
		if _, err := io.ReadFull(c, rest[:]); err != nil {
			c.Close()
			t.Fatalf("connect reply body: %v", err)
		}
	case 4: // IPv6: 16+2
		var rest [18]byte
		if _, err := io.ReadFull(c, rest[:]); err != nil {
			c.Close()
			t.Fatalf("connect reply body v6: %v", err)
		}
	default:
		c.Close()
		t.Fatalf("connect reply: неизвестный atyp=%d", head[3])
	}
	return c
}

// echoSession шлёт payload размера n через SOCKS5 и сверяет SHA-256 эха.
// Клиент читает ровно n байт, поэтому проверка не зависит от того, как
// прокси/стек обрабатывают полузакрытие.
func echoSession(t *testing.T, proxyAddr string, n int) {
	t.Helper()
	c := socks5Connect(t, proxyAddr, net.IPv4(10, 0, 0, 1), 7777)
	defer c.Close()

	payload := make([]byte, n)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("payload entropy: %v", err)
	}
	want := sha256.Sum256(payload)

	writeErr := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		// Сигнал конца: эхо-сервер увидит EOF и закроет соединение после
		// отдачи всех данных. Поддерживается gVisor netstack и TCP.
		if err == nil {
			if cw, ok := c.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
			}
		}
		writeErr <- err
	}()

	h := sha256.New()
	buf := make([]byte, 32*1024)
	for total := 0; total < n; {
		m, err := c.Read(buf)
		if m > 0 {
			h.Write(buf[:m])
			total += m
		}
		if err != nil {
			t.Fatalf("echo read at %d/%d: %v", total, n, err)
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("payload write: %v", err)
	}
	if !bytes.Equal(h.Sum(nil), want[:]) {
		t.Fatalf("SHA-256 mismatch: payload %d bytes повреждён в тракте SOCKS->WG->netstack->echo", n)
	}
}

// abruptSession обрывает сессию в середине записи — сервер обязан пережить.
func abruptSession(t *testing.T, proxyAddr string, n int) {
	t.Helper()
	c := socks5Connect(t, proxyAddr, net.IPv4(10, 0, 0, 1), 7777)
	defer c.Close()
	payload := make([]byte, n)
	rand.Read(payload)
	if _, err := c.Write(payload[:n/2]); err != nil {
		t.Fatalf("abrupt write: %v", err)
	}
	// defer c.Close() — резкий обрыв без полузакрытия.
}

func countFDs() int {
	targets, ok := fdTargets()
	if !ok {
		return -1 // не Linux — проверка недоступна, это не провал
	}
	return len(targets)
}

// fdTargets возвращает отсортированные цели ссылок /proc/self/fd (без
// служебного dirfd самой нумерации). Позволяет в случае утечки назвать
// конкретный «лишний» дескриптор, а не только число.
func fdTargets() ([]string, bool) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, false
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		target, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil {
			continue // fd исчез между ReadDir и Readlink — норма
		}
		if target == "/proc/self/fd" {
			continue // dirfd самого перечисления
		}
		out = append(out, target)
	}
	sort.Strings(out)
	return out, true
}

// checkNoFDLeak сравнивает множества целей fd до/после и называет новые.
// Асинхронное закрытие последнего соединения может не успеть завершиться к
// моменту проверки (CI: свежий socket оставался живым при PASSED-кворуме
// горутин), поэтому множество целей опрашивается с ограниченным бюджетом:
// настоящая утечка держит fd вечно и по-прежнему проваливает тест, а
// закрывающийся сокет лишь откладывает PASS, не превращаясь в FAIL.
func checkNoFDLeak(t *testing.T, phase string, baseline []string, haveBaseline bool) {
	t.Helper()
	if !haveBaseline {
		return
	}
	const settleBudget = 5 * time.Second
	deadline := time.Now().Add(settleBudget)
	var now []string
	var fresh []string
	for {
		var ok bool
		now, ok = fdTargets()
		if !ok {
			return
		}
		base := make(map[string]bool, len(baseline))
		for _, s := range baseline {
			base[s] = true
		}
		fresh = fresh[:0]
		for _, s := range now {
			if !base[s] {
				fresh = append(fresh, s)
			}
		}
		if len(fresh) == 0 {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("утечка дескрипторов (%s): новые цели %v (baseline %d дескрипторов, стало %d) — не закрылись за %v",
		phase, fresh, len(baseline), len(now), settleBudget)
}

func waitForGoroutineQuiesce(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		now := runtime.NumGoroutine()
		if now <= baseline+3 {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("goroutines не возвратились: baseline=%d now=%d\nСтеки:\n%s",
				baseline, now, buf[:n])
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestSocks5LifecycleIntegrityTeardownNoLeaks — см. комментарий в шапке файла.
func TestSocks5LifecycleIntegrityTeardownNoLeaks(t *testing.T) {
	_, aPrivHex, _, aPubB64 := x25519Pair(t)
	bPrivB64, _, bPubHex, _ := x25519Pair(t)

	_, udpA := startEchoDevice(t, aPrivHex, bPubHex)

	confB := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.0.0.2/24
MTU = 1280

[Peer]
PublicKey = %s
AllowedIPs = 10.0.0.0/24
Endpoint = 127.0.0.1:%d
PersistentKeepalive = 25
`, bPrivB64, aPubB64, udpA)

	// Продакшн-функция поднять userspace WG (устройство B + tnetB).
	devB, tnetB, err := startUserspaceWireGuard(confB)
	if err != nil {
		t.Fatalf("startUserspaceWireGuard(B): %v", err)
	}
	defer devB.Close()

	// Продакшн-функция SOCKS5-сервера на реальном TCP 127.0.0.1.
	socksPort := freePort(t, "tcp")
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvErr := make(chan error, 1)
	go func() { srvErr <- runSocks5Server(ctx, socksAddr, tnetB) }()

	// Ждём готовности слушателя (runSocks5Server слушает сам, порт внутрь
	// не отдаёт — поэтому предварительно выбранный свободный порт).
	deadline := time.Now().Add(5 * time.Second)
	for {
		probe, err := net.DialTimeout("tcp", socksAddr, time.Second)
		if err == nil {
			probe.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SOCKS-сервер не начал слушать %s: %v", socksAddr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Прогрев: одна полная сессия, чтобы WG-рукопожатие и стек вышли на
	// установившийся режим до замера baseline'а.
	echoSession(t, socksAddr, 32*1024)

	baselineGoroutines := runtime.NumGoroutine()
	baselineFDs, haveFDs := fdTargets()

	// 1) Целостность на серии сессий разных размеров.
	for _, size := range []int{64 * 1024, 128 * 1024, 256 * 1024, 64 * 1024, 128 * 1024} {
		echoSession(t, socksAddr, size)
	}

	// 2) Резкие обрывы в середине передачи, затем сервер обязан работать.
	abruptSession(t, socksAddr, 128*1024)
	abruptSession(t, socksAddr, 256*1024)
	echoSession(t, socksAddr, 64*1024)

	// 3) Утечки до остановки: после закрытий все per-session горутины и fd
	// должны вернуться к baseline'у.
	waitForGoroutineQuiesce(t, baselineGoroutines)
	checkNoFDLeak(t, "после сессий", baselineFDs, haveFDs)

	// 4) Отмена контекста: runSocks5Server обязан вернуть nil быстро,
	// слушатель обязан закрыться.
	cancel()
	select {
	case err := <-srvErr:
		if err != nil {
			t.Fatalf("runSocks5Server после отмены контекста: %v (ожидали nil)", err)
		}
	case <-time.After(5 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("runSocks5Server не завершился за 5s после отмены контекста\nСтеки:\n%s", buf[:n])
	}

	// 5) Слушатель реально закрыт: новые подключения должны отбрасываться.
	if c, err := net.DialTimeout("tcp", socksAddr, 2*time.Second); err == nil {
		c.Close()
		t.Fatalf("слушатель SOCKS не закрыт после отмены контекста: подключение прошло")
	}

	// 6) Финальная проверка goroutine/fd после остановки сервера.
	waitForGoroutineQuiesce(t, baselineGoroutines)
	checkNoFDLeak(t, "после teardown", baselineFDs, haveFDs)
}
