from otp_manager import OTPManager


url = "otpauth-migration://offline?data=CmsKCsOh..."  # add your qr code link
otpgen = OTPManager()

# Load accounts from migration link
otpgen.load_from_url(url)

# List all loaded entries
for entry in otpgen.list_entries():
    print(entry)

# Get current OTPs
for label, otp in otpgen.get_current_otps().items():
    print(f"{label}: {otp}")
