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

package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/smtp"
	"time"

	"github.com/Dev-Gopi/otp-sdk/otp"
)

func main() {
	// Initialize the OTP SDK with custom maxAttempts and expirationTime
	otpService, err := otp.Initialize("localhost:6379", "", 0, 3, 5*time.Minute)
	if err != nil {
		log.Fatalf("Failed to initialize OTP service: %v", err)
	}

	http.HandleFunc("/generate", generateHandler(otpService))
	http.HandleFunc("/verify", verifyHandler(otpService))
	http.HandleFunc("/resend", resendHandler(otpService))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func generateHandler(otpService *otp.NewOTP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req otp.EmailRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp, otpCode, err := otpService.GenerateOTP(req.Email)
		if err != nil {
			handleError(w, err)
			return
		}

		// Here you can call your external email sending function
		sendEmail(req.Email, otpCode)

		json.NewEncoder(w).Encode(resp)
	}
}

func verifyHandler(otpService *otp.NewOTP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req otp.VerifyRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp, err := otpService.VerifyOTP(req)
		if err != nil {
			handleError(w, err)
			return
		}

		json.NewEncoder(w).Encode(resp)
	}
}

func resendHandler(otpService *otp.NewOTP) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req otp.EmailRequest
		json.NewDecoder(r.Body).Decode(&req)

		resp, otpCode, err := otpService.ResendOTP(req.Email)
		if err != nil {
			handleError(w, err)
			return
		}

		// Here you can call your external email sending function
		sendEmail(req.Email, otpCode)

		json.NewEncoder(w).Encode(resp)
	}
}

func handleError(w http.ResponseWriter, err error) {
	var otpErr *otp.OTPError
	if errors.As(err, &otpErr) {
		http.Error(w, otpErr.Message, http.StatusBadRequest)
	} else {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func sendEmail(to string, otp string) error {
	from := "your-email@example.com"
	password := "your-email-password"
	smtpHost := "smtp.example.com"
	smtpPort := "587"

	auth := smtp.PlainAuth("", from, password, smtpHost)
	message := []byte("Subject: OTP Verification\n\nYour OTP is " + otp)
	toAddresses := []string{to}
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, toAddresses, message)
}
