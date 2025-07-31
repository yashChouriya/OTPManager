# 🔐 OTPManager

A lightweight Python utility to import, manage, and generate **TOTP (Time-based One-Time Passwords)** from Google Authenticator **migration QR codes** (i.e., `otpauth-migration://offline?...`). This tool uses Google's protocol buffer format to decode secrets and generate OTP codes — just like what you see in the Google Authenticator app.

---

## ✨ Features

- ✅ Import TOTP accounts from Google Authenticator migration links
- ✅ Generate 6-digit OTP codes that sync with your authenticator app
- ✅ Add, remove, and list entries
- ✅ Save/load from local database file (`payload.db`)
- ✅ Clean Python class for use in scripts or apps

---

## 📦 Requirements

- Python 3.7+
- `protobuf==5.28.0`

Install dependencies:

```bash
pip install protobuf==5.28.0
```

---

## 📁 Setup

You need the `payload_pb2.py` file using the `payload.proto` schema.

Place `payload_pb2.py` in the same directory as your script.

---

## 🚀 Usage Example

```python
from otp_manager import OTPManager

otpgen = OTPManager()

# Load TOTP accounts from Google Authenticator export URL
otpgen.load_from_url("otpauth-migration://offline?data=...")

# List all accounts
for entry in otpgen.list_entries():
    print(entry)

# Get current OTPs
codes = otpgen.get_current_otps()
for label, otp in codes.items():
    print(f"{label}: {otp}")
```

---

## 🧩 Class Overview

### `OTPManager(db_path="payload.db")`

- Initializes the OTP manager with an optional database file.

### `load_from_url(url)`

- Parses a Google Authenticator migration URL and loads secrets.

### `get_current_otps() → dict`

- Returns a dictionary of account labels and their current OTP codes.

### `list_entries() → list`

- Returns details for each stored account.

### `add_entry(name, issuer, base32_secret)`

- Adds a new TOTP entry.

### `remove_entry(index)`

- Removes the entry at the given index.

---

## 🛠️ Generating `payload_pb2.py` (Optional)

1. Install protoc 5.28.0

2. Save this as `payload.proto`:

   ```proto
   syntax = "proto3";
   message Payload {
     repeated OtpParameters otp_parameters = 1;
     int32 version = 2;
     int32 batch_size = 3;
     int32 batch_index = 4;
     int32 batch_id = 5;
   }

   message OtpParameters {
     bytes secret = 1;
     string name = 2;
     string issuer = 3;
     enum Algorithm {
       ALGORITHM_UNSPECIFIED = 0;
       ALGORITHM_SHA1 = 1;
       ALGORITHM_SHA256 = 2;
       ALGORITHM_SHA512 = 3;
       ALGORITHM_MD5 = 4;
     }
     Algorithm algorithm = 4;

     enum DigitCount {
       DIGIT_COUNT_UNSPECIFIED = 0;
       DIGIT_COUNT_SIX = 1;
       DIGIT_COUNT_EIGHT = 2;
     }
     DigitCount digits = 5;

     enum OtpType {
       OTP_TYPE_UNSPECIFIED = 0;
       OTP_TYPE_HOTP = 1;
       OTP_TYPE_TOTP = 2;
     }
     OtpType type = 6;

     uint64 counter = 7;
   }
   ```

3. Compile:

   ```bash
   protoc --python_out=. payload.proto
   ```

---

## 📂 File Structure

```
project/
│
├── otp_manager.py         # Contains OTPManager class
├── payload_pb2.py         # Generated protobuf schema
├── usage.py                # Example usage
└── README.md
```

---

## 📄 License

MIT License – use freely, modify responsibly.

---

Let me know if you'd like this converted into a full Python package or published to PyPI!
