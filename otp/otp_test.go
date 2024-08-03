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
	"errors"
	"testing"
	"time"
)

var redisAddr = "localhost:6379"
var redisPassword = ""
var redisDB = 0

func setup() *NewOTP {
	otpService, err := Initialize(redisAddr, redisPassword, redisDB, 3, 5*time.Minute)
	if err != nil {
		panic(err)
	}
	return otpService
}

func TestGenerateOTP(t *testing.T) {
	otpService := setup()

	email := "test@example.com"
	resp, otpCode, err := otpService.GenerateOTP(email)
	if err != nil {
		t.Errorf("Failed to generate OTP: %v", err)
	}

	if resp.Token == "" || otpCode == "" {
		t.Errorf("Generated token or OTP is empty")
	}
}

func TestVerifyOTP(t *testing.T) {
	otpService := setup()

	email := "test@example.com"
	resp, otpCode, err := otpService.GenerateOTP(email)
	if err != nil {
		t.Fatalf("Failed to generate OTP: %v", err)
	}

	req := VerifyRequest{
		Email: email,
		OTP:   otpCode,
		Token: resp.Token,
	}

	verifyResp, err := otpService.VerifyOTP(req)
	if err != nil {
		t.Errorf("Failed to verify OTP: %v", err)
		return
	}

	if !verifyResp.Status {
		t.Errorf("Expected verification to succeed, but it failed")
	}
}

func TestVerifyOTPInvalid(t *testing.T) {
	otpService := setup()

	email := "test@example.com"
	resp, _, err := otpService.GenerateOTP(email)
	if err != nil {
		t.Fatalf("Failed to generate OTP: %v", err)
	}

	req := VerifyRequest{
		Email: email,
		OTP:   "000000", // Use a wrong OTP for testing
		Token: resp.Token,
	}

	_, err = otpService.VerifyOTP(req)

	if err != nil {
		t.Errorf("Expected an error for wrong OTP, but got none")
	}
}

func TestResendOTP(t *testing.T) {
	otpService := setup()

	email := "test@example.com"
	resp, otpCode, err := otpService.ResendOTP(email)
	if err != nil {
		t.Errorf("Failed to resend OTP: %v", err)
	}

	if resp.Token == "" || otpCode == "" {
		t.Errorf("Resent token or OTP is empty")
	}
}

func TestRedisConnectionFailure(t *testing.T) {
	_, err := Initialize("invalid:6379", "", 0, 3, 5*time.Minute)
	if err == nil {
		t.Errorf("Expected an error for invalid Redis connection, but got none")
	}

	if !errors.As(err, &ErrRedisConnection) {
		t.Errorf("Expected a Redis connection error, but got a different error")
	}
}

func TestResendOTPWaitBeforeResend(t *testing.T) {
	otpService := setup()

	email := "test@example.com"
	_, _, err := otpService.GenerateOTP(email)
	if err != nil {
		t.Fatalf("Failed to generate OTP: %v", err)
	}

	// Attempt to resend OTP immediately
	_, _, err = otpService.ResendOTP(email)
	if err == nil {
		t.Errorf("Expected an error for resending OTP too soon, but got none")
	}

	if otpErr, ok := err.(*OTPError); !ok || otpErr.Code != "ERR_WAIT_BEFORE_RESEND" {
		t.Errorf("Expected ERR_WAIT_BEFORE_RESEND error, but got %v", err)
	}
}
