# OTP Package

This OTP package provides functionality for generating, sending, and verifying one-time passwords (OTPs) using Redis. It includes OTP generation, verification, and resend functionalities with session token management to ensure secure and reliable OTP handling.

## Features

- Generate and send OTPs via email
- Verify OTPs and session tokens
- Resend OTPs with rate limiting
- Store OTPs and session tokens in Redis
- Handle OTP expiration and maximum attempts
- Custom error handling

## Installation

To install this package, you'll need Go installed on your machine. You can download and install it from the official [Go website](https://golang.org/dl/).

Next, install the Redis client for Go:

```bash
go get github.com/go-redis/redis/v8
go get github.com/dev-gopi/otp-sdk
```

## Prerequisites

This package relies on Redis for storing OTPs and session tokens. You must have Redis installed and running on your machine or server.

### Installing Redis

#### On macOS

You can install Redis using Homebrew:

```bash
brew install redis
brew services start redis
```

On Ubuntu
You can install Redis using apt:

bash
Copy code

```bash
sudo apt update
sudo apt install redis-server
sudo systemctl enable redis-server.service
sudo systemctl start redis-server.service
```

On Windows
You can follow the instructions on the Redis website to download and install Redis on Windows.

Configuring Redis
By default, this package connects to Redis at localhost:6379. If your Redis server is running on a different host or port, or requires authentication, you can configure these settings when initializing the package.

## Usage

### Initialize Redis Client

To use the OTP package, you first need to initialize the Redis client and set up the `NewOTP` struct. The `Initialize` function will create and return an instance of the `NewOTP` struct:

```go
import (
 "time"
 "github.com/go-redis/redis/v8"
 "github.com/dev-gopi/otp-sdk/otp"
)

func main() {
 redisAddr := "localhost:6379"
 redisPassword := ""
 redisDB := 0
 maxAttempts := 3
 expirationTime := 5 * time.Minute

 otpService, err := otp.Initialize(redisAddr, redisPassword, redisDB, maxAttempts, expirationTime)
 if err != nil {
  panic(err)
 }
}
```

### Generate OTP

To generate and send an OTP, use the `GenerateOTP` method:

```go
email := "user@example.com"
response, otp, err := otpService.GenerateOTP(email)
if err != nil {
 panic(err)
}
fmt.Printf("Generated OTP: %s\n", otp)
fmt.Printf("Token: %s\n", response.Token)
```

### Verify OTP

To verify the provided OTP and session token, use the `VerifyOTP` method:

```go
verifyRequest := VerifyRequest{
 Email: "user@example.com",
 OTP:   "123456",
 Token: "generated-session-token",
}

verifyResponse, err := otpService.VerifyOTP(verifyRequest)
if err != nil {
 fmt.Printf("Verification failed: %v\n", err)
} else {
 fmt.Printf("Verification status: %v\n", verifyResponse.Status)
}
```

### Resend OTP

To resend a new OTP, use the `ResendOTP` method:

```go
email := "user@example.com"
response, otp, err := otpService.ResendOTP(email)
if err != nil {
 panic(err)
}
fmt.Printf("Resent OTP: %s\n", otp)
fmt.Printf("Token: %s\n", response.Token)
```

## Data Structures

### NewOTP

The `NewOTP` struct holds the Redis client and context, and configuration options such as maximum attempts and OTP expiration time.

### OTP

The `OTP` struct holds the OTP code, maximum attempts, issued time, and expiration time.

### SessionToken

The `SessionToken` struct holds the session token, issued time, expiration time, usage status, and the number of attempts.

### EmailRequest

The `EmailRequest` struct holds the email address for OTP generation.

### VerifyRequest

The `VerifyRequest` struct holds the email address, OTP code, and session token for verification.

### EmailResponse

The `EmailResponse` struct holds the token, status, issued time, and expiration time for the email response.

### VerifyResponse

The `VerifyResponse` struct holds the verification message, status, and token for the verification response.

## Error Handling

The package provides custom error messages for different scenarios such as:

- `ErrRedisConnection`: Redis connection error
- `ErrGenerateOTP`: Error generating OTP
- `ErrGenerateToken`: Error generating token
- `ErrInvalidOTP`: Invalid OTP
- `ErrExpiredOTP`: Expired OTP
- `ErrTokenUsed`: Token already used
- `ErrMaxAttempts`: Maximum attempts reached
- `ErrWaitBeforeResend`: Wait before resending OTP

### Example Error Handling

```go
err := otpService.GenerateOTP("user@example.com")
if err != nil {
 switch err {
 case ErrRedisConnection:
  fmt.Println("Error connecting to Redis:", err)
 case ErrGenerateOTP:
  fmt.Println("Error generating OTP:", err)
 default:
  fmt.Println("An unexpected error occurred:", err)
 }
}
```

## Helper Functions

### generateRandomOTP

Generates a random 6-digit OTP.

### generateRandomToken

Generates a random session token.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

Author: Gopi  
Git URL: [https://github.com/dev-gopi/otp-sdk](https://github.com/dev-gopi/otp-sdk)

---

This README provides an overview of the OTP package, its usage, and configuration. For further details or contributions, please refer to the source code or contact the maintainer.
