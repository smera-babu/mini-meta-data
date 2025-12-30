import os
import hashlib
import exifread
from PyPDF2 import PdfReader
from docx import Document
from datetime import datetime

def generate_hash(file_path):
    hash_md5 = hashlib.md5()
    hash_sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
            hash_sha256.update(chunk)

    return hash_md5.hexdigest(), hash_sha256.hexdigest()

def file_metadata(file_path):
    stats = os.stat(file_path)
    metadata = {
        "File Name": os.path.basename(file_path),
        "File Size (Bytes)": stats.st_size,
        "Created Time": datetime.fromtimestamp(stats.st_ctime),
        "Modified Time": datetime.fromtimestamp(stats.st_mtime),
        "Accessed Time": datetime.fromtimestamp(stats.st_atime)
    }
    return metadata


def image_metadata(file_path):
    image_data = {}
    with open(file_path, 'rb') as img:
        tags = exifread.process_file(img)
        for tag in tags:
            image_data[tag] = str(tags[tag])
    return image_data

def pdf_metadata(file_path):
    reader = PdfReader(file_path)
    return reader.metadata

def docx_metadata(file_path):
    doc = Document(file_path)
    return doc.core_properties

def main():
    file_path = input("Enter file path: ")

    if not os.path.exists(file_path):
        print("File not found!")
        return

    print("\n--- BASIC FILE METADATA ---")
    meta = file_metadata(file_path)
    for k, v in meta.items():
        print(f"{k}: {v}")

    md5, sha256 = generate_hash(file_path)
    print("\nMD5:", md5)
    print("SHA256:", sha256)

    ext = file_path.lower().split('.')[-1]

    if ext in ['jpg', 'jpeg', 'png']:
        print("\n--- IMAGE METADATA ---")
        img_meta = image_metadata(file_path)
        for k, v in img_meta.items():
            print(f"{k}: {v}")

    elif ext == 'pdf':
        print("\n--- PDF METADATA ---")
        pdf_meta = pdf_metadata(file_path)
        print(pdf_meta)

    elif ext == 'docx':
        print("\n--- DOCX METADATA ---")
        doc_meta = docx_metadata(file_path)
        print(doc_meta)

    print("\nForensic Analysis Completed Successfully.")

if __name__ == "__main__":
    main()
