package pkg

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// TokenClaims untuk JWT dengan extended fields
type TokenClaims struct {
	UserID      string            `json:"user_id"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	Role        string            `json:"role"`
	Permissions []string          `json:"permissions"`
	TokenID     string            `json:"token_id"`
	TokenType   string            `json:"token_type"`
	DeviceID    string            `json:"device_id,omitempty"`
	IPAddress   string            `json:"ip_address,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	jwt.RegisteredClaims
}

// TokenPair untuk return multiple tokens
type TokenPair struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	ExpiresIn        int64     `json:"expires_in"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	Scope            string    `json:"scope,omitempty"`
}

// VerificationToken struct
type VerificationToken struct {
	Token     string            `json:"token"`
	Hash      string            `json:"hash"`
	Type      string            `json:"type"`
	ExpiresAt time.Time         `json:"expires_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// APIKeyToken struct
type APIKeyToken struct {
	Key       string     `json:"key"`
	Secret    string     `json:"secret"`
	Hash      string     `json:"hash"`
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// OTPToken struct
type OTPToken struct {
	Code      string    `json:"code"`
	Secret    string    `json:"secret"`
	ExpiresAt time.Time `json:"expires_at"`
	Type      string    `json:"type"` // numeric, alphanumeric, totp
}

// TokenGenerator configuration
type TokenGenerator struct {
	JWTSecret          []byte
	AccessExpiry       time.Duration
	RefreshExpiry      time.Duration
	VerificationExpiry time.Duration
	OTPExpiry          time.Duration
	DefaultIssuer      string
	DefaultAudience    string
}

// TokenGeneratorConfig untuk konfigurasi yang lebih fleksibel
type TokenGeneratorConfig struct {
	JWTSecret          string
	AccessExpiry       time.Duration
	RefreshExpiry      time.Duration
	VerificationExpiry time.Duration
	OTPExpiry          time.Duration
	Issuer             string
	Audience           string
}

// NewTokenGenerator creates a new token generator with default config
func NewTokenGenerator(secret string) *TokenGenerator {
	return &TokenGenerator{
		JWTSecret:          []byte(secret),
		AccessExpiry:       15 * time.Minute,
		RefreshExpiry:      7 * 24 * time.Hour,
		VerificationExpiry: 24 * time.Hour,
		OTPExpiry:          5 * time.Minute,
		DefaultIssuer:      "token-service",
		DefaultAudience:    "api",
	}
}

// NewTokenGeneratorWithConfig creates token generator with custom config
func NewTokenGeneratorWithConfig(config TokenGeneratorConfig) *TokenGenerator {
	tg := &TokenGenerator{
		JWTSecret:       []byte(config.JWTSecret),
		DefaultIssuer:   config.Issuer,
		DefaultAudience: config.Audience,
	}

	// Set defaults if not provided
	if config.AccessExpiry == 0 {
		tg.AccessExpiry = 15 * time.Minute
	} else {
		tg.AccessExpiry = config.AccessExpiry
	}

	if config.RefreshExpiry == 0 {
		tg.RefreshExpiry = 7 * 24 * time.Hour
	} else {
		tg.RefreshExpiry = config.RefreshExpiry
	}

	if config.VerificationExpiry == 0 {
		tg.VerificationExpiry = 24 * time.Hour
	} else {
		tg.VerificationExpiry = config.VerificationExpiry
	}

	if config.OTPExpiry == 0 {
		tg.OTPExpiry = 5 * time.Minute
	} else {
		tg.OTPExpiry = config.OTPExpiry
	}

	return tg
}

// ============= BASIC TOKEN GENERATORS =============

// GenerateRandomString dengan charset yang bisa dipilih
func GenerateRandomString(length int, charset string) (string, error) {
	if charset == "" {
		charset = AlphanumericCharset
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}

	return string(bytes), nil
}

// GenerateSecureRandomString menggunakan crypto/rand dengan strength level
func GenerateSecureRandomString(strength string) (string, error) {
	var length int
	var charset string

	switch strength {
	case TokenStrengthLow:
		length = 8
		charset = NumericCharset
	case TokenStrengthMedium:
		length = 32
		charset = AlphanumericCharset
	case TokenStrengthHigh:
		length = 64
		charset = AlphanumericCharset + SpecialCharset
	default:
		length = 32
		charset = AlphanumericCharset
	}

	return GenerateRandomString(length, charset)
}

// GenerateRandomBytes dan encode ke berbagai format
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

func GenerateRandomBase64(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func GenerateRandomHex(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func GenerateRandomBase32(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(bytes), nil
}

// GenerateBase58 (Bitcoin-style encoding)
func GenerateRandomBase58(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return encodeBase58(bytes), nil
}

func encodeBase58(data []byte) string {
	var result []byte

	for _, b := range data {
		carry := int(b)
		for i := 0; i < len(result); i++ {
			carry += int(result[i]) * 256
			result[i] = byte(carry % 58)
			carry /= 58
		}

		for carry > 0 {
			result = append(result, byte(carry%58))
			carry /= 58
		}
	}

	// Convert to string
	var encoded string
	for i := len(result) - 1; i >= 0; i-- {
		encoded += string(Base58Charset[result[i]])
	}

	return encoded
}

// ============= UUID GENERATORS =============

func GenerateUUID() string {
	return uuid.New().String()
}

func GenerateShortUUID() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

func GenerateNumericUUID() string {
	id := uuid.New()
	hash := sha256.Sum256(id[:])
	return fmt.Sprintf("%x", hash[:8])
}

// ============= SPECIALIZED TOKENS =============

// GenerateOTP - One Time Password
func (tg *TokenGenerator) GenerateOTP(digits int, otpType string) (*OTPToken, error) {
	var code string
	var err error

	switch otpType {
	case "numeric":
		code, err = generateNumericOTP(digits)
	case "alphanumeric":
		code, err = GenerateRandomString(digits, AlphanumericCharset)
	case "totp":
		code, err = generateTOTP()
	default:
		code, err = generateNumericOTP(6)
	}

	if err != nil {
		return nil, err
	}

	secret, err := GenerateRandomBase32(32)
	if err != nil {
		return nil, err
	}

	return &OTPToken{
		Code:      code,
		Secret:    secret,
		ExpiresAt: time.Now().Add(tg.OTPExpiry),
		Type:      otpType,
	}, nil
}

func generateNumericOTP(digits int) (string, error) {
	max := int64(1)
	for i := 0; i < digits; i++ {
		max *= 10
	}

	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%0*d", digits, n.Int64()), nil
}

func generateTOTP() (string, error) {
	// Simplified TOTP implementation
	_ = time.Now().Unix() / 30 // 30-second window
	return generateNumericOTP(6)
}

// GenerateCSRFToken - Cross-Site Request Forgery token
func GenerateCSRFToken() (string, error) {
	return GenerateRandomBase64(32)
}

// GenerateSessionToken - Session management token
func (tg *TokenGenerator) GenerateSessionToken(userID string) (string, error) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	data := fmt.Sprintf("%s:%s", userID, timestamp)

	// Create HMAC
	h := hmac.New(sha256.New, tg.JWTSecret)
	h.Write([]byte(data))
	signature := hex.EncodeToString(h.Sum(nil))

	// Combine data and signature
	token := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s.%s", data, signature)))
	return token, nil
}

// ============= API KEY GENERATION =============

func (tg *TokenGenerator) GenerateAPIKey(prefix string, expiry *time.Duration) (*APIKeyToken, error) {
	// Generate key part
	keyBytes, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	// Generate secret part
	secretBytes, err := GenerateRandomBytes(32)
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%s_%s", prefix, base64.URLEncoding.EncodeToString(keyBytes))
	secret := base64.URLEncoding.EncodeToString(secretBytes)

	// Create hash for database storage
	combined := fmt.Sprintf("%s:%s", key, secret)
	hash, err := bcrypt.GenerateFromPassword([]byte(combined), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	apiKey := &APIKeyToken{
		Key:       key,
		Secret:    secret,
		Hash:      string(hash),
		Prefix:    prefix,
		CreatedAt: time.Now(),
	}

	if expiry != nil {
		expiresAt := time.Now().Add(*expiry)
		apiKey.ExpiresAt = &expiresAt
	}

	return apiKey, nil
}

// ============= VERIFICATION TOKENS =============

func (tg *TokenGenerator) GenerateVerificationToken(userID, tokenType string, metadata map[string]string) (*VerificationToken, error) {
	// Generate token
	token, err := GenerateRandomString(32, URLSafeCharset)
	if err != nil {
		return nil, err
	}

	// Create hash with timestamp and user ID
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	combined := fmt.Sprintf("%s:%s:%s:%s", userID, token, tokenType, timestamp)
	hash := sha256.Sum256([]byte(combined))

	return &VerificationToken{
		Token:     token,
		Hash:      hex.EncodeToString(hash[:]),
		Type:      tokenType,
		ExpiresAt: time.Now().Add(tg.VerificationExpiry),
		Metadata:  metadata,
	}, nil
}

func (tg *TokenGenerator) GenerateEmailVerificationToken(userID, email string) (*VerificationToken, error) {
	metadata := map[string]string{
		"email": email,
		"type":  "email_verification",
	}
	return tg.GenerateVerificationToken(userID, TokenTypeEmailVerification, metadata)
}

func (tg *TokenGenerator) GeneratePasswordResetToken(userID, email string) (*VerificationToken, error) {
	metadata := map[string]string{
		"email": email,
		"type":  "password_reset",
	}
	return tg.GenerateVerificationToken(userID, TokenTypePasswordReset, metadata)
}

// ============= JWT TOKEN GENERATION =============

func (tg *TokenGenerator) GenerateJWTToken(claims *TokenClaims, expiry time.Duration) (string, error) {
	now := time.Now()

	// Set standard claims
	claims.RegisteredClaims = jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
		NotBefore: jwt.NewNumericDate(now),
		Issuer:    tg.DefaultIssuer,
		Audience:  []string{tg.DefaultAudience},
		Subject:   claims.UserID,
	}

	// Generate token ID if not provided
	if claims.TokenID == "" {
		claims.TokenID = GenerateUUID()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(tg.JWTSecret)
}

func (tg *TokenGenerator) GenerateTokenPair(userID, username, email, role string, permissions []string, metadata map[string]string) (*TokenPair, error) {
	tokenID := GenerateUUID()
	now := time.Now()

	// Access Token Claims
	accessClaims := &TokenClaims{
		UserID:      userID,
		Username:    username,
		Email:       email,
		Role:        role,
		Permissions: permissions,
		TokenID:     tokenID,
		TokenType:   TokenTypeAccess,
		Metadata:    metadata,
	}

	accessToken, err := tg.GenerateJWTToken(accessClaims, tg.AccessExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Refresh Token Claims (minimal claims untuk security)
	refreshClaims := &TokenClaims{
		UserID:    userID,
		Username:  username,
		TokenID:   tokenID,
		TokenType: TokenTypeRefresh,
	}

	refreshToken, err := tg.GenerateJWTToken(refreshClaims, tg.RefreshExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		TokenType:        "Bearer",
		ExpiresIn:        int64(tg.AccessExpiry.Seconds()),
		ExpiresAt:        now.Add(tg.AccessExpiry),
		RefreshExpiresAt: now.Add(tg.RefreshExpiry),
		Scope:            strings.Join(permissions, " "),
	}, nil
}

// ============= TOKEN VALIDATION =============

func (tg *TokenGenerator) ValidateJWTToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tg.JWTSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		// Additional validation
		if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
			return nil, fmt.Errorf("token expired")
		}

		if claims.NotBefore != nil && claims.NotBefore.Time.After(time.Now()) {
			return nil, fmt.Errorf("token not valid yet")
		}

		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

func (tg *TokenGenerator) ValidateSessionToken(tokenString, userID string) error {
	// Decode token
	data, err := base64.URLEncoding.DecodeString(tokenString)
	if err != nil {
		return fmt.Errorf("invalid token format")
	}

	parts := strings.Split(string(data), ".")
	if len(parts) != 2 {
		return fmt.Errorf("invalid token structure")
	}

	// Verify HMAC
	h := hmac.New(sha256.New, tg.JWTSecret)
	h.Write([]byte(parts[0]))
	expectedSignature := hex.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(parts[1]), []byte(expectedSignature)) {
		return fmt.Errorf("invalid token signature")
	}

	// Check user ID
	dataParts := strings.Split(parts[0], ":")
	if len(dataParts) != 2 || dataParts[0] != userID {
		return fmt.Errorf("token user mismatch")
	}

	return nil
}

func ValidateAPIKey(providedKey, providedSecret, storedHash string) error {
	combined := fmt.Sprintf("%s:%s", providedKey, providedSecret)
	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(combined))
}

// ============= UTILITY FUNCTIONS =============

func (tg *TokenGenerator) HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (tg *TokenGenerator) CreateTokenFingerprint(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:8]) // First 8 bytes for fingerprint
}

func (tg *TokenGenerator) IsTokenExpired(expiresAt time.Time) bool {
	return time.Now().After(expiresAt)
}
