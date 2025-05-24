# HTTP-GET DoS Attack Simulation

## Overview

This project demonstrates an HTTP-GET Denial-of-Service (DoS) attack against a Python-based HTTP server and the effectiveness of various defense mechanisms. The repository contains two main scripts:

* **httpServer.py**: Implements a simple HTTP server with configurable defenses (rate limiting, CAPTCHA, and Proof-of-Work).
* **attackServer.py**: Simulates an HTTP-GET flood attack using multi-threading and HTTP Keep-Alive to overwhelm the server.

By running the attack against the server with different defense configurations, you can observe how each mechanism affects the server's resilience.

---

## Clone Repository:

```shell
git clone https://github.com/Shayhha/DoS
```

## Configuration

### Server Configuration (`httpServer.py`)

Edit the following flags in the script to enable or disable specific defenses:

```python
USE_RATE_LIMIT = True  # Enforce IP rate limiting
USE_CAPTCHA = True     # Enforce CAPTCHA challenge
USE_POW = True         # Enforce Proof-of-Work challenge
```

Configure HTTP server IP and port:

```python
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8090
```

### Attack Configuration (`attackServer.py`)

Set these flags in the attack script to configure how it attempts to bypass server defenses:

```python
ATTACK_RATE_LIMIT = True  # Spoof X-Forwarded-For IP to bypass rate limit
ATTACK_CAPTCHA = True     # Automatically solve and submit CAPTCHA
ATTACK_POW = True         # Attempt to solve Proof-of-Work challenge
```

Configure target HTTP server IP and port:

```python
TARGET_IP = '127.0.0.1'
TARGET_PORT = 8090
```

---

## Usage

### Starting the HTTP Server

Launch the server after configuring the defense flags in the script:

```bash
python httpServer.py
```

### Running the HTTP-GET DoS Attack

After configuring the flags and target address, launch the DoS attack:

```bash
python attackServer.py
```

The attack script sends a flood of HTTP GET requests using multiple threads and keeps connections alive using the HTTP Keep-Alive header.

---

## Defense Mechanisms

### 1. Rate Limiting

Limits the number of requests a client IP can make per time unit. Once the limit is exceeded, subsequent requests receive a 429 Too Many Requests response.

### 2. CAPTCHA Challenge

A basic CAPTCHA is used to challenge clients and ensure they're not automated scripts. The attack script includes logic to bypass this by solving and submitting it automatically.

### 3. Proof-of-Work (PoW)

Clients are required to solve a cryptographic puzzle (e.g., finding a nonce that produces a hash with a certain number of leading zeros). Higher difficulty settings make the challenge computationally expensive and slow down attack attempts.

---

## Observations & Results

1. **Without Defenses**:

   * The server is easily overwhelmed by the flood. Connections pile up, CPU and memory spike, and the server crashes within seconds.

2. **Rate Limiting and CAPTCHA Only**:

   * The attack can bypass rate limiting using spoofed IPs and defeat CAPTCHA challenges if automated correctly. The server is still vulnerable under high load.

3. **All Defenses Active (Rate Limiting + CAPTCHA + Proof-of-Work)**:

   * The Proof-of-Work mechanism significantly slows down attack attempts. Combined with rate limiting and CAPTCHA, the server remains operational under attack.

---

## License

This project is licensed under the [MIT License](LICENSE).

© All rights reserved to Shayhha (Shay Hahiashvili).

**Note:** This application should be used responsibly and in compliance with applicable laws and regulations. Unauthorized use is strictly prohibited.
