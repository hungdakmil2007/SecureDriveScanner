# Author: Nguyen Hung Tran
# Final project - ITSC203

import hashlib


# Course requirement - Function and File handling:
# Calculate the SHA256 hash of a file without executing it
def calculate_sha256(file_path):
    try:
        sha256_hash = hashlib.sha256()

        # Read the file in binary mode because any file type can be hashed
        with open(file_path, "rb") as file:
            while True:
                file_block = file.read(4096)

                if not file_block:
                    break

                sha256_hash.update(file_block)

        return sha256_hash.hexdigest(), None

    except OSError as error:
        return None, str(error)