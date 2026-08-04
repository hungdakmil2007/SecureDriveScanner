# Author: Nguyen Hung Tran
# Course Project - ITSC203

import os
import re

from finding import Finding


# Text-based file types supported in Phase 3
SUPPORTED_TEXT_EXTENSIONS = {
    ".txt",
    ".csv",
    ".log",
    ".py",
    ".json",
    ".xml",
    ".html"
}


# Pattern for possible email addresses
EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

# Pattern for possible Canadian or North American phone numbers
PHONE_PATTERN = (
    r"(?<!\d)"
    r"(?:\+?1[\s.-]?)?"
    r"(?:\(\d{3}\)|\d{3})"
    r"[\s.-]\d{3}[\s.-]\d{4}"
    r"(?!\d)"
)

# Pattern for possible password values
PASSWORD_PATTERN = (
    r"(?i)\b(?:password|passwd|pwd|passcode)\b"
    r"\s*[:=]\s*[\"']?([^\s\"',;]+)"
)

# Pattern for possible API key values
API_KEY_PATTERN = (
    r"(?i)\b(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\b"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{8,})"
)

# Pattern for possible token values
TOKEN_PATTERN = (
    r"(?i)\b(?:bearer[_-]?token|access[_-]?token|auth[_-]?token|token)\b"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{8,})"
)

# Pattern for common private key headers
PRIVATE_KEY_PATTERN = (
    r"(?i)-----BEGIN "
    r"(?:RSA |EC |DSA |OPENSSH )?"
    r"PRIVATE KEY-----"
)

# Check whether the file is a supported text-based file
def is_supported_text_file(file_path):
    extension = os.path.splitext(file_path)[1].lower()

    return extension in SUPPORTED_TEXT_EXTENSIONS


# Hide part of an email before storing it in the report
def mask_email(email):
    local_part, domain = email.split("@", 1)

    if len(local_part) <= 2:
        masked_local = local_part[0] + "***"
    else:
        masked_local = local_part[:2] + "***"

    return masked_local + "@" + domain

# Hide most digits of a phone number before storing it
def mask_phone(phone):
    digits = re.sub(r"\D", "", phone)

    if len(digits) < 4:
        return "[MASKED]"

    return "***-***-" + digits[-4:]

# Hide the complete password before storing it
def mask_password(password):
    return "[MASKED]"

# Hide most of a secret value before storing it
def mask_secret(secret):
    if len(secret) <= 6:
        return "[MASKED]"

    return secret[:3] + "***" + secret[-3:]

# Read one text file and check each line for possible email addresses
def scan_text_file(file_path):
    findings = []

    if not is_supported_text_file(file_path):
        return findings, None

    try:
        # Course requirement - File handling:
        # Read the text file one line at a time
        with open(file_path, "r", encoding="utf-8") as text_file:
            for line_number, line in enumerate(text_file, start=1):
                #check for possible email
                email_matches = re.findall(EMAIL_PATTERN, line)

                for email in email_matches:
                    masked_email = mask_email(email)

                    finding = Finding(
                        file_path,
                        "Possible email address",
                        "Email address pattern found in a text file",
                        5,
                        line_number,
                        masked_email
                    )

                    findings.append(finding)

                # Check the same line for possible phone numbers
                phone_matches = re.findall(PHONE_PATTERN, line)

                for phone in phone_matches:
                    masked_phone = mask_phone(phone)

                    finding = Finding(
                        file_path,
                        "Possible phone number",
                        "Phone number pattern found in a text file",
                        5,
                        line_number,
                        masked_phone
                    )

                    findings.append(finding)

                # Check the same line for possible password values
                password_matches = re.findall(PASSWORD_PATTERN, line)

                for password in password_matches:
                    masked_password = mask_password(password)

                    finding = Finding(
                        file_path,
                        "Possible password value",
                        "Password-related value found in a text file",
                        20,
                        line_number,
                        masked_password
                    )

                    findings.append(finding)

                # Check the same line for possible API key values
                api_key_matches = re.findall(API_KEY_PATTERN, line)

                for api_key in api_key_matches:
                    masked_api_key = mask_secret(api_key)

                    finding = Finding(
                        file_path,
                        "Possible API key",
                        "API key pattern found in a text file",
                        25,
                        line_number,
                        masked_api_key
                    )

                    findings.append(finding)

                # Check the same line for possible token values
                token_matches = re.findall(TOKEN_PATTERN, line)

                for token in token_matches:
                    masked_token = mask_secret(token)

                    finding = Finding(
                        file_path,
                        "Possible token",
                        "Token pattern found in a text file",
                        25,
                        line_number,
                        masked_token
                    )

                    findings.append(finding)
                # Check the same line for a private key indicator
                private_key_match = re.search(PRIVATE_KEY_PATTERN, line)

                if private_key_match is not None:
                    finding = Finding(
                        file_path,
                        "Possible private key",
                        "Private key header found in a text file",
                        30,
                        line_number,
                        "[PRIVATE KEY HEADER DETECTED]"
                    )

                    findings.append(finding)

    except (OSError, UnicodeDecodeError) as error:
        return findings, str(error)

    return findings, None