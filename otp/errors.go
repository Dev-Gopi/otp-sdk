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
	"fmt"
)

type ErrorHandler interface {
	Error(err *OTPError) string
}

type OTPError struct {
	Code    string
	Message string
}

func (e *OTPError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

var (
	ErrRedisConnection  = &OTPError{Code: "ERR_REDIS_CONNECTION", Message: "Failed to connect to Redis"}
	ErrGenerateOTP      = &OTPError{Code: "ERR_GENERATE_OTP", Message: "Failed to generate OTP"}
	ErrGenerateToken    = &OTPError{Code: "ERR_GENERATE_TOKEN", Message: "Failed to generate token"}
	ErrInvalidOTP       = &OTPError{Code: "ERR_INVALID_OTP", Message: "Invalid OTP"}
	ErrExpiredOTP       = &OTPError{Code: "ERR_EXPIRED_OTP", Message: "OTP expired"}
	ErrTokenUsed        = &OTPError{Code: "ERR_TOKEN_USED", Message: "Token already used"}
	ErrMaxAttempts      = &OTPError{Code: "ERR_MAX_ATTEMPTS", Message: "Maximum attempts exceeded"}
	ErrWaitBeforeResend = &OTPError{Code: "ERR_WAIT_BEFORE_RESEND", Message: "Please wait before requesting a new OTP"}
)
