// Project: otp-sdk
// Package otp provides functionalities for generating, sending, and verifying OTPs using Redis.
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author: Gopi
// Git URL: [https://github.com/dev-gopi/otp-sdk]

package otp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/go-redis/redis/v8"
)

// OTPService defines the methods for generating, sending, verifying, and resending OTPs
type OTPService interface {
	GenerateOTP(email string) (*EmailResponse, string, error)
	VerifyOTP(req VerifyRequest) (*VerifyResponse, error)
	ResendOTP(email string) (*EmailResponse, string, error)
}

// NewOTP struct to hold Redis client and context
type NewOTP struct {
	rdb            *redis.Client
	ctx            context.Context
	maxAttempts    int
	expirationTime time.Duration
}

// OTP and SessionToken structures
type OTP struct {
	CodeHash    string
	MaxAttempts int
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

type SessionToken struct {
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Used      bool
	Attempts  int
}

type EmailRequest struct {
	Email string `json:"email"`
}

type VerifyRequest struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
	Token string `json:"token"`
}

type EmailResponse struct {
	Token     string    `json:"token"`
	Status    bool      `json:"status"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type VerifyResponse struct {
	Message string `json:"message,omitempty"`
	Status  bool   `json:"status"`
	Token   string `json:"token,omitempty"`
}

// Initialize initializes the Redis client and returns a NewOTP struct
func Initialize(redisAddr, redisPassword string, redisDB int, maxAttempts int, expirationTime time.Duration) (*NewOTP, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       redisDB,
	})
	ctx := context.Background()

	// Test Redis connection
	err := rdb.Ping(ctx).Err()
	if err != nil {
		return nil, fmt.Errorf("redis connection error: %s", err.Error())
	}

	// Set default values if not provided
	if maxAttempts == 0 {
		maxAttempts = 3
	}
	if expirationTime == 0 {
		expirationTime = 5 * time.Minute
	}

	return &NewOTP{rdb: rdb, ctx: ctx, maxAttempts: maxAttempts, expirationTime: expirationTime}, nil
}

// GenerateOTP generates an OTP and stores it along with a session token in Redis
func (n *NewOTP) GenerateOTP(email string) (*EmailResponse, string, error) {
	otp := generateRandomOTP()
	otpHash := hashOTP(otp)
	token := generateRandomToken()
	issuedAt := time.Now()
	expiration := issuedAt.Add(5 * time.Minute)

	otpData := OTP{CodeHash: otpHash, MaxAttempts: n.maxAttempts, IssuedAt: issuedAt, ExpiresAt: expiration}
	tokenData := SessionToken{Token: token, IssuedAt: issuedAt, ExpiresAt: expiration}

	otpKey := fmt.Sprintf("otp:%s", email)
	tokenKey := fmt.Sprintf("token:%s:%s", token, email)

	otpJson, _ := json.Marshal(otpData)
	tokenJson, _ := json.Marshal(tokenData)

	oldTokenKeyPattern := fmt.Sprintf("token:*:%s", email)
	keys, _ := n.rdb.Keys(n.ctx, oldTokenKeyPattern).Result()
	n.rdb.Del(n.ctx, keys...)

	err := n.rdb.Set(n.ctx, otpKey, otpJson, n.expirationTime).Err()
	if err != nil {
		return nil, "", fmt.Errorf("generate OTP error: %s", err.Error())
	}

	err = n.rdb.Set(n.ctx, tokenKey, tokenJson, n.expirationTime).Err()
	if err != nil {
		return nil, "", fmt.Errorf("generate token error: %s", err.Error())
	}

	return &EmailResponse{Token: token, Status: true, IssuedAt: issuedAt, ExpiresAt: expiration}, otp, nil
}

// VerifyOTP verifies the provided OTP and session token
func (n *NewOTP) VerifyOTP(req VerifyRequest) (*VerifyResponse, error) {
	otpKey := fmt.Sprintf("otp:%s", req.Email)
	tokenKey := fmt.Sprintf("token:%s:%s", req.Token, req.Email)
	attemptTokenKeyPattern := fmt.Sprintf("token:*:%s", req.Email)

	otpJson, err := n.rdb.Get(n.ctx, otpKey).Result()
	if err == redis.Nil {
		return nil, ErrExpiredOTP
	} else if err != nil {
		return nil, fmt.Errorf("failed to verify OTP: %w", err)
	}

	latestTokenJson, err := n.rdb.Get(n.ctx, tokenKey).Result()
	if err == redis.Nil {
		return nil, ErrExpiredOTP
	} else if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	var otp OTP
	var token SessionToken
	json.Unmarshal([]byte(otpJson), &otp)
	json.Unmarshal([]byte(latestTokenJson), &token)

	if token.Used {
		return nil, ErrTokenUsed
	}

	if time.Now().After(otp.ExpiresAt) {
		keys, _ := n.rdb.Keys(n.ctx, attemptTokenKeyPattern).Result()
		keys = append(keys, otpKey, tokenKey)
		n.rdb.Del(n.ctx, keys...)
		return nil, ErrExpiredOTP
	}

	otpHash := hashOTP(req.OTP)
	if token.Token != req.Token || otp.CodeHash != otpHash {
		token.Used = true
		token.Attempts++
		tokenJsonBytes, _ := json.Marshal(token)
		tokenJsonStr := string(tokenJsonBytes)
		n.rdb.Set(n.ctx, tokenKey, tokenJsonStr, time.Until(otp.ExpiresAt))

		if token.Attempts >= n.maxAttempts {
			keys, _ := n.rdb.Keys(n.ctx, attemptTokenKeyPattern).Result()
			keys = append(keys, otpKey, tokenKey)
			n.rdb.Del(n.ctx, keys...)
			return nil, ErrMaxAttempts
		} else {
			newToken := generateRandomToken()
			newTokenKey := fmt.Sprintf("token:%s:%s", newToken, req.Email)
			issuedAt := time.Now()
			token.Token = newToken
			token.IssuedAt = issuedAt
			token.Used = false
			tokenJsonBytes, _ = json.Marshal(token)
			tokenJsonStr = string(tokenJsonBytes)
			n.rdb.Set(n.ctx, newTokenKey, tokenJsonStr, time.Until(otp.ExpiresAt))
			return &VerifyResponse{Message: "Invalid OTP or Token. New token generated.", Token: newToken}, nil
		}
	}

	token.Used = true
	tokenJsonBytes, _ := json.Marshal(token)
	tokenJsonStr := string(tokenJsonBytes)
	n.rdb.Set(n.ctx, tokenKey, tokenJsonStr, time.Until(token.ExpiresAt))

	keys, _ := n.rdb.Keys(n.ctx, attemptTokenKeyPattern).Result()
	keys = append(keys, otpKey, tokenKey)
	n.rdb.Del(n.ctx, keys...)

	return &VerifyResponse{Status: true}, nil
}

// ResendOTP resends a new OTP and token to the user
func (n *NewOTP) ResendOTP(email string) (*EmailResponse, string, error) {
	otpKey := fmt.Sprintf("otp:%s", email)
	tokenKey := fmt.Sprintf("token:*:%s", email)

	otpJson, err := n.rdb.Get(n.ctx, otpKey).Result()
	if err != nil && err != redis.Nil {
		return nil, "", fmt.Errorf("redis error: %w", err)
	}

	var otp OTP
	json.Unmarshal([]byte(otpJson), &otp)

	if time.Since(otp.IssuedAt) < 1*time.Minute {
		return nil, "", ErrWaitBeforeResend
	}

	keys, _ := n.rdb.Keys(n.ctx, tokenKey).Result()
	keys = append(keys, otpKey)
	n.rdb.Del(n.ctx, keys...)

	newOtp := generateRandomOTP()
	newOtpHash := hashOTP(newOtp)
	newToken := generateRandomToken()
	issuedAt := time.Now()
	expiration := issuedAt.Add(n.expirationTime)

	latestTokenKey := fmt.Sprintf("token:%s:%s", newToken, email)
	otpData := OTP{CodeHash: newOtpHash, IssuedAt: issuedAt, ExpiresAt: expiration}
	tokenData := SessionToken{Token: newToken, IssuedAt: issuedAt, ExpiresAt: expiration, Attempts: 0}

	otpJsonBytes, _ := json.Marshal(otpData)
	otpJson = string(otpJsonBytes)
	tokenJsonBytes, _ := json.Marshal(tokenData)
	tokenJson := string(tokenJsonBytes)

	err = n.rdb.Set(n.ctx, otpKey, otpJson, n.expirationTime).Err()
	if err != nil {
		return nil, "", fmt.Errorf("generate OTP error: %s", err.Error())
	}

	err = n.rdb.Set(n.ctx, latestTokenKey, tokenJson, n.expirationTime).Err()
	if err != nil {
		return nil, "", fmt.Errorf("generate token error: %s", err.Error())
	}

	return &EmailResponse{Token: newToken, Status: true, IssuedAt: issuedAt, ExpiresAt: expiration}, newOtp, nil
}

// generateRandomOTP generates a random 6-digit OTP
func generateRandomOTP() string {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		// Fallback in case of error
		return fmt.Sprintf("%06d", 123456)
	}
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

// generateRandomToken generates a random token
func generateRandomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// hashOTP hashes the given OTP using SHA-256
func hashOTP(otp string) string {
	hash := sha256.Sum256([]byte(otp))
	return hex.EncodeToString(hash[:])
}
