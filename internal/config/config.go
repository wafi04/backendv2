package config

import (
	"os"
	"strconv"
	"time"
)

type AppConfig struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	Redis    RedisConfig    `json:"redis"`
	Email    EmailConfig    `json:"email"`
	Storage  StorageConfig  `json:"storage"`
	JWT      JWTConfig      `json:"jwt"`
	Log      LogConfig      `json:"log"`
}

type ServerConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	Environment  string        `json:"environment"`
}

type JWTConfig struct {
	SecretKey      string        `json:"secret_key"`
	ExpiredTime    time.Duration `json:"expired_time"`
	RefreshExpired time.Duration `json:"refresh_expired"`
}

type DatabaseConfig struct {
	Driver   string `json:"driver"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
}

type RedisConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
}

type EmailConfig struct {
	SMTPHost string `json:"smtp_host"`
	SMTPPort int    `json:"smtp_port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
}

type StorageConfig struct {
	Provider   string `json:"provider"`
	BucketName string `json:"bucket_name"`
	Region     string `json:"region"`
	AccessKey  string `json:"access_key"`
	SecretKey  string `json:"secret_key"`
}

type LogConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
	Output string `json:"output"`
}

func LoadConfig() *AppConfig {
	return &AppConfig{
		Server: ServerConfig{
			Host:         GetEnv("SERVER_HOST", "localhost"),
			Port:         GetEnvInt("SERVER_PORT", 8080),
			ReadTimeout:  GetEnvDuration("READ_TIMEOUT", 10*time.Second),
			WriteTimeout: GetEnvDuration("WRITE_TIMEOUT", 10*time.Second),
			Environment:  GetEnv("ENVIRONMENT", "development"),
		},
		Database: DatabaseConfig{
			Driver:   GetEnv("DB_DRIVER", "postgres"),
			Host:     GetEnv("DB_HOST", "localhost"),
			Port:     GetEnvInt("DB_PORT", 5432),
			User:     GetEnv("DB_USERNAME", "postgres"),
			Password: GetEnv("DB_PASSWORD", "postgres"),
			Database: GetEnv("DB_DATABASE", "backend"),
		},
		Redis: RedisConfig{
			Host:     GetEnv("REDIS_HOST", "localhost"),
			Port:     GetEnvInt("REDIS_PORT", 6379),
			Password: GetEnv("REDIS_PASSWORD", ""),
		},
		JWT: JWTConfig{
			SecretKey:      GetEnv("JWT_SECRET", "secret"),
			ExpiredTime:    GetEnvDuration("JWT_EXPIRED", 24*time.Hour),
			RefreshExpired: GetEnvDuration("JWT_REFRESH_EXPIRED", 168*time.Hour),
		},
	}
}

func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func GetEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func GetEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
