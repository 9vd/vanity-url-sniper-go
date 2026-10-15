package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/buger/jsonparser"
	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
)

type Config struct {
	WSURL              string
	APIHost            string
	TokenFile          string
	OurGuildID         string
	PatchToken         string
	Password           string
	H2SessionCount     int
	TLSSocketCount     int
	MFARefreshInterval time.Duration
}

var CONFIG = Config{
	WSURL:              "wss://gateway.discord.gg/?v=9&encoding=json",
	APIHost:            "canary.discord.com",
	TokenFile:          "list.txt",
	OurGuildID:         "1538971513414226010",
	PatchToken:         "",
	Password:           "shyevils",
	H2SessionCount:     11,
	TLSSocketCount:     11,
	MFARefreshInterval: 5 * time.Minute,
}

const (
	UA     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	XPROPS = "eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0="
)

type CacheEntry struct {
	Vanity  string
	Boosts  int
	TLSBuf  []byte
	BodyBuf []byte
}

var (
	tokens        []string
	guildCache    = make(map[string]*CacheEntry)
	cacheMutex    sync.RWMutex
	mfaToken      string
	mfaMutex      sync.RWMutex
	h2Clients     []*http.Client
	h2Mutex       sync.RWMutex
	tlsSockets    []net.Conn
	tlsMutex      sync.RWMutex
	requestIdPool = make(chan string, 500)
	globalCounter uint64
	firedGuilds   sync.Map
)

func generateRequestId() string {
	select {
	case id := <-requestIdPool:
		return id
	default:
		b := make([]byte, 16)
		rand.Read(b)
		return hex.EncodeToString(b)
	}
}

func initPool() {
	go func() {
		for {
			b := make([]byte, 16)
			rand.Read(b)
			requestIdPool <- hex.EncodeToString(b)
		}
	}()
}

func loadTokens() bool {
	dir, _ := os.Getwd()
	tokenPath := filepath.Join(dir, CONFIG.TokenFile)
	file, err := os.Open(tokenPath)
	if err != nil {
		return false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			tokens = append(tokens, line)
		}
	}
	return len(tokens) > 0
}

func getTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
		},
	}
}

func createTLSSocket(index int) net.Conn {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", CONFIG.APIHost+":443", getTLSConfig(CONFIG.APIHost))
	if err != nil {
		return nil
	}
	tcpConn, ok := conn.NetConn().(*net.TCPConn)
	if ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(5 * time.Second)
	}
	go func(c net.Conn, idx int) {
		reader := bufio.NewReader(c)
		for {
			resp, err := http.ReadResponse(reader, nil)
			if err != nil {
				tlsMutex.Lock()
				if idx < len(tlsSockets) && tlsSockets[idx] == c {
					tlsSockets[idx] = nil
				}
				tlsMutex.Unlock()
				c.Close()
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			bodyStr := string(body)
			if len(body) > 0 && !strings.Contains(bodyStr, "gateway.discord.gg") && !strings.Contains(bodyStr, "\"url\":") {
				count := atomic.AddUint64(&globalCounter, 1)
				fmt.Printf("[t%d] %s\n", count, bodyStr)
			}
		}
	}(conn, index)
	return conn
}

func getMFA() string {
	mfaMutex.RLock()
	defer mfaMutex.RUnlock()
	return mfaToken
}

func setMFA(val string) {
	mfaMutex.Lock()
	mfaToken = val
	mfaMutex.Unlock()
}

func updateCache(guildID, vanity string, boostCount int) (oldBoosts int, existed bool) {
	if guildID == "" {
		return 0, false
	}
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	entry, ok := guildCache[guildID]
	if !ok {
		var tlsBuf []byte
		var bodyBuf []byte
		if vanity != "" && vanity != "null" {
			body := fmt.Sprintf(`{"code":"%s"}`, vanity)
			bodyBuf = []byte(body)
			mfa := getMFA()
			reqStr := fmt.Sprintf(
				"PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"Authorization: %s\r\n"+
					"Content-Type: application/json\r\n"+
					"Accept-Encoding: identity\r\n"+
					"User-Agent: %s\r\n"+
					"X-Super-Properties: %s\r\n"+
					"X-Discord-Mfa-Authorization: %s\r\n"+
					"Content-Length: %d\r\n"+
					"Connection: keep-alive\r\n\r\n%s",
				CONFIG.OurGuildID, CONFIG.APIHost, CONFIG.PatchToken, UA, XPROPS, mfa, len(bodyBuf), body,
			)
			tlsBuf = []byte(reqStr)
		}
		guildCache[guildID] = &CacheEntry{
			Vanity:  vanity,
			Boosts:  boostCount,
			TLSBuf:  tlsBuf,
			BodyBuf: bodyBuf,
		}
		return 0, false
	}

	oldBoosts = entry.Boosts
	entry.Boosts = boostCount

	vToUse := entry.Vanity
	if vanity != "" && vanity != "null" {
		vToUse = vanity
		entry.Vanity = vanity
	}

	if vToUse != "" && vToUse != "null" {
		body := fmt.Sprintf(`{"code":"%s"}`, vToUse)
		bodyBuf := []byte(body)
		mfa := getMFA()
		reqStr := fmt.Sprintf(
			"PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Authorization: %s\r\n"+
				"Content-Type: application/json\r\n"+
				"Accept-Encoding: identity\r\n"+
				"User-Agent: %s\r\n"+
				"X-Super-Properties: %s\r\n"+
				"X-Discord-Mfa-Authorization: %s\r\n"+
				"Content-Length: %d\r\n"+
				"Connection: keep-alive\r\n\r\n%s",
			CONFIG.OurGuildID, CONFIG.APIHost, CONFIG.PatchToken, UA, XPROPS, mfa, len(bodyBuf), body,
		)
		entry.TLSBuf = []byte(reqStr)
		entry.BodyBuf = bodyBuf
	}

	return oldBoosts, true
}

func rebuildAllCaches() {
	cacheMutex.RLock()
	type item struct {
		vanity string
		boosts int
	}
	entries := make(map[string]item)
	for gID, entry := range guildCache {
		if entry.Vanity != "" {
			entries[gID] = item{vanity: entry.Vanity, boosts: entry.Boosts}
		}
	}
	cacheMutex.RUnlock()
	for gID, it := range entries {
		updateCache(gID, it.vanity, it.boosts)
	}
}

func getMfaToken() bool {
	h2Mutex.RLock()
	var client *http.Client
	if len(h2Clients) > 0 {
		client = h2Clients[0]
	}
	h2Mutex.RUnlock()
	if client == nil {
		return false
	}
	reqURL := fmt.Sprintf("https://%s/api/v9/guilds/%s/vanity-url", CONFIG.APIHost, CONFIG.OurGuildID)
	req1, _ := http.NewRequest("PATCH", reqURL, bytes.NewBufferString(`{"code":""}`))
	req1.Header.Set("Authorization", CONFIG.PatchToken)
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("User-Agent", UA)
	req1.Header.Set("X-Super-Properties", XPROPS)
	req1.Header.Set("X-Request-Id", generateRequestId())
	resp1, err := client.Do(req1)
	if err != nil {
		return false
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(resp1.Body)
	ticket, err := jsonparser.GetString(body1, "mfa", "ticket")
	if err != nil {
		ticket, _ = jsonparser.GetString(body1, "ticket")
	}
	mfaBody, _ := json.Marshal(map[string]string{"ticket": ticket, "mfa_type": "password", "data": CONFIG.Password})
	finishURL := fmt.Sprintf("https://%s/api/v9/mfa/finish", CONFIG.APIHost)
	req2, _ := http.NewRequest("POST", finishURL, bytes.NewBuffer(mfaBody))
	req2.Header.Set("Authorization", CONFIG.PatchToken)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("User-Agent", UA)
	req2.Header.Set("X-Super-Properties", XPROPS)
	req2.Header.Set("X-Request-Id", generateRequestId())
	resp2, err := client.Do(req2)
	if err != nil {
		return false
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	token, err := jsonparser.GetString(body2, "token")
	if err == nil && token != "" {
		setMFA(token)
		rebuildAllCaches()
		return true
	}
	return false
}

func fireVanity(guildID string) bool {
	cacheMutex.RLock()
	cached, ok := guildCache[guildID]
	cacheMutex.RUnlock()
	if !ok || cached == nil || cached.BodyBuf == nil || cached.TLSBuf == nil {
		return false
	}
	h2Mutex.RLock()
	for _, client := range h2Clients {
		if client == nil {
			continue
		}
		go func(c *http.Client, body []byte) {
			reqURL := fmt.Sprintf("https://%s/api/v9/guilds/%s/vanity-url", CONFIG.APIHost, CONFIG.OurGuildID)
			req, _ := http.NewRequest("PATCH", reqURL, bytes.NewReader(body))
			req.Header.Set("Authorization", CONFIG.PatchToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Encoding", "identity")
			req.Header.Set("User-Agent", UA)
			req.Header.Set("X-Super-Properties", XPROPS)
			req.Header.Set("X-Discord-Mfa-Authorization", getMFA())
			req.Header.Set("X-Request-Id", generateRequestId())
			resp, err := c.Do(req)
			if err == nil {
				rBody, _ := io.ReadAll(resp.Body)
				count := atomic.AddUint64(&globalCounter, 1)
				fmt.Printf("[h%d] %s\n", count, string(rBody))
				resp.Body.Close()
			}
		}(client, cached.BodyBuf)
	}
	h2Mutex.RUnlock()
	tlsMutex.Lock()
	for i := len(tlsSockets) - 1; i >= 0; i-- {
		s := tlsSockets[i]
		if s != nil {
			s.Write(cached.TLSBuf)
		} else {
			go func(idx int, buf []byte) {
				conn := createTLSSocket(idx)
				if conn != nil {
					conn.Write(buf)
					tlsMutex.Lock()
					tlsSockets[idx] = conn
					tlsMutex.Unlock()
				}
			}(i, cached.TLSBuf)
		}
	}
	tlsMutex.Unlock()
	return true
}

func fetchAndClaimVanity(guildID string) {
	h2Mutex.RLock()
	var client *http.Client
	if len(h2Clients) > 0 {
		client = h2Clients[0]
	}
	h2Mutex.RUnlock()
	if client == nil {
		return
	}
	reqURL := fmt.Sprintf("https://%s/api/v9/guilds/%s/vanity-url", CONFIG.APIHost, guildID)
	req, _ := http.NewRequest("GET", reqURL, nil)
	req.Header.Set("Authorization", CONFIG.PatchToken)
	req.Header.Set("User-Agent", UA)
	req.Header.Set("X-Super-Properties", XPROPS)
	req.Header.Set("X-Request-Id", generateRequestId())
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	code, err := jsonparser.GetString(body, "code")
	if err == nil && len(code) > 0 {
		patchVanity(code)
	}
}

func patchVanity(vanity string) {
	body := fmt.Sprintf(`{"code":"%s"}`, vanity)
	bodyBuf := []byte(body)
	mfa := getMFA()
	reqStr := fmt.Sprintf(
		"PATCH /api/v9/guilds/%s/vanity-url HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Authorization: %s\r\n"+
			"Content-Type: application/json\r\n"+
			"Accept-Encoding: identity\r\n"+
			"User-Agent: %s\r\n"+
			"X-Super-Properties: %s\r\n"+
			"X-Discord-Mfa-Authorization: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n\r\n%s",
		CONFIG.OurGuildID, CONFIG.APIHost, CONFIG.PatchToken, UA, XPROPS, mfa, len(bodyBuf), body,
	)
	tlsBuf := []byte(reqStr)
	h2Mutex.RLock()
	for _, client := range h2Clients {
		if client == nil {
			continue
		}
		go func(c *http.Client) {
			reqURL := fmt.Sprintf("https://%s/api/v9/guilds/%s/vanity-url", CONFIG.APIHost, CONFIG.OurGuildID)
			req, _ := http.NewRequest("PATCH", reqURL, bytes.NewReader(bodyBuf))
			req.Header.Set("Authorization", CONFIG.PatchToken)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Encoding", "identity")
			req.Header.Set("User-Agent", UA)
			req.Header.Set("X-Super-Properties", XPROPS)
			req.Header.Set("X-Discord-Mfa-Authorization", mfa)
			req.Header.Set("X-Request-Id", generateRequestId())
			resp, err := c.Do(req)
			if err == nil {
				rBody, _ := io.ReadAll(resp.Body)
				count := atomic.AddUint64(&globalCounter, 1)
				fmt.Printf("[h%d] %s\n", count, string(rBody))
				resp.Body.Close()
			}
		}(client)
	}
	h2Mutex.RUnlock()
	tlsMutex.Lock()
	for i := len(tlsSockets) - 1; i >= 0; i-- {
		s := tlsSockets[i]
		if s != nil {
			s.Write(tlsBuf)
		}
	}
	tlsMutex.Unlock()
}

func connectGatewayListener(token string, index int) {
	u, _ := url.Parse(CONFIG.WSURL)
	header := make(http.Header)
	header.Set("User-Agent", UA)
	dialer := websocket.Dialer{TLSClientConfig: getTLSConfig(u.Hostname()), HandshakeTimeout: 30 * time.Second}
	c, _, err := dialer.Dial(u.String(), header)
	if err != nil {
		time.Sleep(1 * time.Second)
		go connectGatewayListener(token, index)
		return
	}
	defer c.Close()
	identifyPayload := map[string]interface{}{
		"op": 2,
		"d": map[string]interface{}{
			"token":        token,
			"capabilities": 16383,
			"properties": map[string]interface{}{
				"os": "Windows", "browser": "Chrome", "device": "", "system_locale": "en-US",
				"browser_user_agent": UA, "browser_version": "125.0.0.0", "os_version": "10", "release_channel": "canary",
			},
			"presence": map[string]interface{}{"status": "online", "since": 0, "activities": []interface{}{}, "afk": false},
			"compress": false, "client_state": map[string]interface{}{"guild_versions": map[string]interface{}{}},
		},
	}
	c.WriteJSON(identifyPayload)
	var lastSequence int64 = -1
	var hbInterval time.Duration = 41250 * time.Millisecond
	hbTicker := time.NewTicker(hbInterval)
	defer hbTicker.Stop()
	go func() {
		for range hbTicker.C {
			var dVal interface{}
			if lastSequence != -1 {
				dVal = lastSequence
			}
			c.WriteJSON(map[string]interface{}{"op": 1, "d": dVal})
		}
	}()
	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			time.Sleep(1 * time.Second)
			go connectGatewayListener(token, index)
			return
		}
		op, _ := jsonparser.GetInt(message, "op")
		if seq, err := jsonparser.GetInt(message, "s"); err == nil {
			lastSequence = seq
		}
		t, _ := jsonparser.GetString(message, "t")
		if t == "READY" {
			jsonparser.ArrayEach(message, func(guild []byte, dataType jsonparser.ValueType, offset int, err error) {
				gID, _ := jsonparser.GetString(guild, "id")
				vCode, _ := jsonparser.GetString(guild, "vanity_url_code")
				bCount, _ := jsonparser.GetInt(guild, "premium_subscription_count")
				if gID != "" {
					updateCache(gID, vCode, int(bCount))
				}
			}, "d", "guilds")
			fmt.Printf("token%d ready\n", index+1)
			continue
		}
		if t == "GUILD_CREATE" {
			gID, _ := jsonparser.GetString(message, "d", "id")
			vCode, _ := jsonparser.GetString(message, "d", "vanity_url_code")
			bCount, _ := jsonparser.GetInt(message, "d", "premium_subscription_count")
			if gID != "" {
				updateCache(gID, vCode, int(bCount))
			}
			continue
		}
		if t == "GUILD_UPDATE" {
			gID, _ := jsonparser.GetString(message, "d", "id")
			vCode, _ := jsonparser.GetString(message, "d", "vanity_url_code")
			boostCount, bErr := jsonparser.GetInt(message, "d", "premium_subscription_count")
			if gID != "" && bErr == nil {
				newBoosts := int(boostCount)
				oldBoosts, existed := updateCache(gID, vCode, newBoosts)
				if existed && oldBoosts >= 14 && newBoosts < 14 {
					if _, loaded := firedGuilds.LoadOrStore(gID, true); !loaded {
						go func(id string) {
							fmt.Printf("[ALERT] Sunucu %s Level 3 kaybetti! (boost: %d -> %d). Vanity patch atılıyor...\n", id, oldBoosts, newBoosts)
							if !fireVanity(id) {
								fetchAndClaimVanity(id)
							}
							time.Sleep(2 * time.Second)
							firedGuilds.Delete(id)
						}(gID)
					}
				}
			}
			continue
		}
		if op == 7 || op == 9 {
			c.Close()
			time.Sleep(1 * time.Second)
			go connectGatewayListener(token, index)
			return
		}
		if op == 10 {
			interval, err := jsonparser.GetInt(message, "d", "heartbeat_interval")
			if err == nil && interval > 0 {
				hbInterval = time.Duration(interval) * time.Millisecond
				hbTicker.Reset(hbInterval)
			}
		}
	}
}

func main() {
	initPool()
	if !loadTokens() {
		os.Exit(1)
	}
	fmt.Printf("tls \"%d\" http2 \"%d\" total patch = \"%d\"\n", CONFIG.TLSSocketCount, CONFIG.H2SessionCount, CONFIG.TLSSocketCount+CONFIG.H2SessionCount)
	tlsSockets = make([]net.Conn, CONFIG.TLSSocketCount)
	for i := 0; i < CONFIG.TLSSocketCount; i++ {
		tlsSockets[i] = createTLSSocket(i)
	}
	h2Clients = make([]*http.Client, CONFIG.H2SessionCount)
	for i := 0; i < CONFIG.H2SessionCount; i++ {
		h2Clients[i] = &http.Client{Transport: &http2.Transport{TLSClientConfig: getTLSConfig(CONFIG.APIHost)}, Timeout: 10 * time.Second}
	}
	getMfaToken()
	for index, token := range tokens {
		go connectGatewayListener(token, index)
		time.Sleep(100 * time.Millisecond)
	}
	go func() {
		ticker := time.NewTicker(CONFIG.MFARefreshInterval)
		for range ticker.C {
			getMfaToken()
		}
	}()
	go func() {
		ticker := time.NewTicker(8 * time.Second)
		for range ticker.C {
			tlsMutex.Lock()
			for i, s := range tlsSockets {
				if s != nil {
					pingReq := fmt.Sprintf("GET /api/v9/gateway HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\n\r\n", CONFIG.APIHost, UA)
					_, err := s.Write([]byte(pingReq))
					if err != nil {
						s.Close()
						tlsSockets[i] = createTLSSocket(i)
					}
				} else {
					tlsSockets[i] = createTLSSocket(i)
				}
			}
			tlsMutex.Unlock()
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}
