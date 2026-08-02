import hashlib


def calculate_sha256(filepath):
    """
    بتاخد مسار الملف وبترجع الـ SHA-256 hash بتاعه
    """
    sha256 = hashlib.sha256()

    # بنقرأ الملف على chunks عشان لو الملف كبير ميأكلش RAM
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)

    return sha256.hexdigest()