import base64
import time
import urllib.parse
import hmac
import os
import payload_pb2

INTERVAL = 30


class OTPManager:
    def __init__(self, db_path="payload.db"):
        self.db_path = db_path
        self.payload = payload_pb2.Payload()
        if os.path.exists(db_path):
            self._read_from_file()

    def _read_from_file(self):
        with open(self.db_path, "rb") as f:
            self.payload.ParseFromString(f.read())

    def _save_to_file(self):
        with open(self.db_path, "wb") as f:
            f.write(self.payload.SerializeToString())

    def load_from_url(self, url: str):
        parsed = urllib.parse.urlparse(url)
        data = urllib.parse.parse_qs(parsed.query)["data"][0]
        bin_data = base64.urlsafe_b64decode(data + "==")
        imported_payload = payload_pb2.Payload()
        imported_payload.ParseFromString(bin_data)
        self.payload.MergeFrom(imported_payload)
        self._save_to_file()

    def add_entry(self, name, issuer, secret_b32):
        try:
            secret = base64.b32decode(
                secret_b32.strip().replace(" ", ""), casefold=True
            )
        except Exception:
            raise ValueError("Invalid Base32 secret.")

        p = self.payload.otp_parameters.add()
        p.secret = secret
        p.name = name
        p.issuer = issuer
        p.algorithm = payload_pb2.Payload.Algorithm.ALGORITHM_SHA1
        p.digits = payload_pb2.Payload.DigitCount.DIGIT_COUNT_SIX
        p.type = payload_pb2.Payload.OtpType.OTP_TYPE_TOTP
        self._save_to_file()

    def list_entries(self):
        return [
            {
                "index": i,
                "issuer": p.issuer,
                "name": p.name,
                "secret": base64.b32encode(p.secret).decode(),
                "type": p.type,
                "digits": p.digits,
            }
            for i, p in enumerate(self.payload.otp_parameters)
        ]

    def remove_entry(self, index):
        if 0 <= index < len(self.payload.otp_parameters):
            del self.payload.otp_parameters[index]
            self._save_to_file()
        else:
            raise IndexError("Invalid index")

    def _generate_totp(self, secret: bytes, counter: int):
        msg = counter.to_bytes(8, "big")
        digest = hmac.new(secret, msg, "sha1").digest()
        offset = digest[19] & 0xF
        code = digest[offset : offset + 4]
        code = int.from_bytes(code, "big") & 0x7FFFFFFF
        return "{:06d}".format(code % 1000000)

    def get_current_otps(self):
        counter = int(time.time() // INTERVAL)
        return {
            f"{p.issuer} ({p.name})": self._generate_totp(p.secret, counter)
            for p in self.payload.otp_parameters
        }

    def get_current_otps_with_remaining(self):
        now = time.time()
        counter = int(now // INTERVAL)
        seconds_remaining = INTERVAL - (int(now) % INTERVAL)

        return {
            f"{p.issuer} ({p.name})": {
                "otp": self._generate_totp(p.secret, counter),
                "expires_in": seconds_remaining,
            }
            for p in self.payload.otp_parameters
        }

    def get_otps_with_min_remaining(self, min_remaining: int = 25, block: bool = True):
        """
        Return current OTPs. If fewer than `min_remaining` seconds remain in this
        30s window and `block` is True, wait until the next window so the returned
        codes have ~30s remaining.

        Returns: { "issuer (name)": {"otp": "123456", "expires_in": int} }
        """
        period = INTERVAL
        now = time.time()
        remaining = period - (now % period)

        if remaining < min_remaining and block:
            # Sleep just past the boundary so we enter the next TOTP window.
            time.sleep(remaining + 0.05)

        now = time.time()
        counter = int(now // period)
        seconds_remaining = int(period - (now % period))

        return [
            {
                "issuer": p.issuer,
                "otp": self._generate_totp(p.secret, counter),
                "expires_in": seconds_remaining,
            }
            for p in self.payload.otp_parameters
        ]

    def get_next_fresh_otps(self):
        """
        Always wait for the next 30s boundary and return brand-new OTPs with
        ~30 seconds remaining.

        Returns: { "issuer (name)": {"otp": "123456", "expires_in": 30} }
        """
        period = INTERVAL
        # Sleep to the very start of the next period
        sleep_for = period - (time.time() % period)
        time.sleep(sleep_for + 0.05)  # small epsilon to cross the boundary

        now = time.time()
        counter = int(now // period)
        seconds_remaining = int(period - (now % period))

        return {
            f"{p.issuer} ({p.name})": {
                "otp": self._generate_totp(p.secret, counter),
                "expires_in": seconds_remaining,
            }
            for p in self.payload.otp_parameters
        }
