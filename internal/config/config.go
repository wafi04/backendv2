package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server ServerConfig `json:"server"`
	Database DatabaseConfig `json:"database"`
	Redis RedisConfig `json:"redis"`
	Email EmailConfig `json:"email"`
	Storage StorageConfig `json:"storage"`
	JWT  JWTConfig  `json:"jwt"`
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

type EmailConfig   struct {
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


func Load() *Config {
    return &Config{
        Server: ServerConfig{
            Host:         getEnv("SERVER_HOST", "localhost"),
            Port:         getEnvInt("SERVER_PORT", 8080),
            ReadTimeout:  getEnvDuration("READ_TIMEOUT", 10*time.Second),
            WriteTimeout: getEnvDuration("WRITE_TIMEOUT", 10*time.Second),
            Environment:  getEnv("ENVIRONMENT", "development"),
        },
        Database: DatabaseConfig{
            Driver:   getEnv("DB_DRIVER", "postgres"),
            Host:     getEnv("DB_HOST", "localhost"),
            Port:     getEnvInt("DB_PORT", 5432),
            User: getEnv("DB_USERNAME", ""),
            Password: getEnv("DB_PASSWORD", ""),
            Database: getEnv("DB_DATABASE", ""),
        },
        Redis: RedisConfig{
            Host:     getEnv("REDIS_HOST", "localhost"),
            Port:     getEnvInt("REDIS_PORT", 6379),
            Password: getEnv("REDIS_PASSWORD", ""),
        },
        JWT: JWTConfig{
            SecretKey:      getEnv("JWT_SECRET", "secret"),
            ExpiredTime:    getEnvDuration("JWT_EXPIRED", 24*time.Hour),
            RefreshExpired: getEnvDuration("JWT_REFRESH_EXPIRED", 168*time.Hour),
        },
    }
}


func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
    if value := os.Getenv(key); value != "" {
        if intValue, err := strconv.Atoi(value); err == nil {
            return intValue
        }
    }
    return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
    if value := os.Getenv(key); value != "" {
        if duration, err := time.ParseDuration(value); err == nil {
            return duration
        }
    }
    return defaultValue
}