package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/juju/ratelimit"
	"github.com/natefinch/lumberjack"
)

// Config represents the configuration for the server.
type Config struct {
	RateLimit   RateLimitConfig `json:"RateLimit"`
	Log         LogConfig       `json:"Log"`
	Cors        CorsConfig      `json:"Cors"`
	RedirectURL string          `json:"RedirectURL"`
	Password    string          `json:"Password"`
}

// RateLimitConfig represents the configuration for rate limiting.
type RateLimitConfig struct {
	Enabled           bool `json:"Enabled"`
	RequestsPerSecond int  `json:"RequestsPerSecond"`
}

// LogConfig represents the configuration for logging.
type LogConfig struct {
	LogFilePath   string `json:"LogFilePath"`
	MaxLogSizeMB  int    `json:"MaxLogSizeMB"`
	MaxBackups    int    `json:"MaxBackups"`
	MaxAgeDays    int    `json:"MaxAge"`
	LogTimeFormat string `json:"LogTimeFormat"`
	TimeZone      string `json:"TimeZone"`
}

// CorsConfig represents the configuration for CORS.
type CorsConfig struct {
	Enabled        bool     `json:"Enabled"`
	AllowedOrigins []string `json:"AllowedOrigins"`
}

// Credentials structure is used for parsing received JSON data.
type Credentials struct {
	Password string `json:"password"`
}

// Response structure is used for returning JSON-formatted response messages.
type Response struct {
	Message string `json:"message"`
	URL     string `json:"url"`
}

// IPBucket stores the token bucket for each IP address.
type IPBucket struct {
	limiter    *ratelimit.Bucket
	lastAccess time.Time
}

// IPBucketMap stores the mapping of IP addresses to their corresponding token buckets.
type IPBucketMap struct {
	mu      sync.Mutex
	buckets map[string]*IPBucket
}

var (
	config    Config
	ipBuckets *IPBucketMap
)

func main() {
	var err error
	config, err = loadConfig("config.json")
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	ipBuckets = newIPBucketMap()

	http.HandleFunc("/", limitMiddleware(rootHandler))
	http.HandleFunc("/verify", limitMiddleware(verifyHandler))

	fmt.Println("Server is running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loadConfig(configPath string) (Config, error) {
	var config Config
	configFile, err := os.Open(configPath)
	if err != nil {
		return config, err
	}
	defer configFile.Close()

	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&config)
	return config, err
}

func newIPBucketMap() *IPBucketMap {
	return &IPBucketMap{
		buckets: make(map[string]*IPBucket),
	}
}

func handleCorsHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	fmt.Printf("%d", len(config.Cors.AllowedOrigins))
	for _, allowed := range config.Cors.AllowedOrigins {
		fmt.Printf("Compare %s,%s", origin, allowed)
		if strings.EqualFold(origin, allowed) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "application/json")
			w.Header().Set("Access-Control-Max-Age", "86900")
		}
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	bucket := ipBuckets.getBucket(clientIP, config.RateLimit)

	if config.RateLimit.Enabled && bucket.TakeAvailable(1) == 0 {
		sendJSONResponse(w, Response{Message: "Rate limit exceeded"}, http.StatusTooManyRequests)
		return
	}

	logAccess(clientIP, config.Log)

	sendJSONResponse(w, Response{
		Message: fmt.Sprintf("Access Denied for IP: %s. Use /verify for password verification.", clientIP),
	}, http.StatusForbidden)
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	bucket := ipBuckets.getBucket(clientIP, config.RateLimit)

	if config.Cors.Enabled {
		handleCorsHeaders(w, r)
	}

	if config.RateLimit.Enabled && bucket.TakeAvailable(1) == 0 {
		sendJSONResponse(w, Response{Message: "Rate limit exceeded"}, http.StatusTooManyRequests)
		return
	}

	if r.Method != http.MethodPost {
		sendJSONResponse(w, Response{Message: "Method not allowed"}, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		sendJSONResponse(w, Response{Message: "Error reading request body"}, http.StatusInternalServerError)
		return
	}

	var creds Credentials
	err = json.Unmarshal(body, &creds)
	if err != nil {
		sendJSONResponse(w, Response{Message: "Error parsing JSON"}, http.StatusBadRequest)
		return
	}

	if creds.Password == config.Password {
		logVerification(clientIP, true, config.Log)
		sendJSONResponse(w, Response{Message: "Succeed", URL: config.RedirectURL}, http.StatusOK)
	} else {
		logVerification(clientIP, false, config.Log)
		sendJSONResponse(w, Response{Message: "Invalid password"}, http.StatusUnauthorized)
	}
}

func limitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		bucket := ipBuckets.getBucket(clientIP, config.RateLimit)

		if config.RateLimit.Enabled && bucket.TakeAvailable(1) == 0 {
			sendJSONResponse(w, Response{Message: "Rate limit exceeded"}, http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}

func sendJSONResponse(w http.ResponseWriter, response Response, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error encoding JSON response", http.StatusInternalServerError)
		return
	}

	w.Write(jsonResponse)
}

func getClientIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
	}

	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}

	return ip
}

func (b *IPBucketMap) getBucket(ip string, rateLimitConfig RateLimitConfig) *ratelimit.Bucket {
	b.mu.Lock()
	defer b.mu.Unlock()

	if bucket, ok := b.buckets[ip]; ok {
		bucket.lastAccess = time.Now()
		return bucket.limiter
	}

	bucket := &IPBucket{
		limiter: ratelimit.NewBucket(time.Second, int64(rateLimitConfig.RequestsPerSecond)),
	}
	b.buckets[ip] = bucket

	return bucket.limiter
}

func logAccess(ip string, logConfig LogConfig) {
	logMessage := fmt.Sprintf("%s - Access attempt", ip)
	logToFile(logMessage, logConfig)
}

func logVerification(ip string, success bool, logConfig LogConfig) {
	status := "Failed"
	if success {
		status = "Succeeded"
	}

	logMessage := fmt.Sprintf("%s - Verification %s", ip, status)
	logToFile(logMessage, logConfig)
}

func logToFile(message string, logConfig LogConfig) {
	file, err := os.OpenFile(logConfig.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("Error opening log file: %v", err)
		return
	}
	defer file.Close()

	logger := log.New(&lumberjack.Logger{
		Filename:   logConfig.LogFilePath,
		MaxSize:    logConfig.MaxLogSizeMB, // max size in megabytes
		MaxBackups: logConfig.MaxBackups,
		MaxAge:     logConfig.MaxAgeDays, // max age in days
	}, "", log.LstdFlags)

	// Load the specified time zone from the configuration
	loc, err := time.LoadLocation(logConfig.TimeZone)
	if err != nil {
		log.Printf("Error loading time zone: %v", err)
		return
	}

	// Set the time zone for the logger
	logger.SetOutput(file)
	logger.SetFlags(0) // Enable timestamp
	logger.SetPrefix("[PWDVerify] ")
	logger.SetOutput(log.New(file, "", log.LstdFlags).Writer()) // Use the file as the output

	// Format the log message with the time zone
	timestamp := time.Now().In(loc).Format(logConfig.LogTimeFormat)
	logMessage := fmt.Sprintf("%s - %s", timestamp, message)

	logger.Println(logMessage)
}
