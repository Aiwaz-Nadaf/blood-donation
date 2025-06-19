import os

def check_uploaded_files():
    print("\n=== Uploaded Files ===")
    print("-" * 50)
    
    upload_folder = 'static/uploads'
    
    if not os.path.exists(upload_folder):
        print(f"Upload folder '{upload_folder}' does not exist.")
        return
    
    files = os.listdir(upload_folder)
    
    if not files:
        print("No files found in the upload folder.")
        return
    
    print(f"Found {len(files)} files in upload folder:")
    for file in files:
        file_path = os.path.join(upload_folder, file)
        file_size = os.path.getsize(file_path)
        print(f"\nFile: {file}")
        print(f"Size: {file_size / 1024:.2f} KB")
        print(f"Path: {file_path}")
        print("-" * 30)

if __name__ == "__main__":
    check_uploaded_files() 