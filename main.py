import os
import time
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from smtplib import SMTPException
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import shutil
import zipfile
import hashlib
import pyzipper
import getpass
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

logging.basicConfig(filename='file_processing.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MyHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.executor = ThreadPoolExecutor(max_workers=5)

    def on_created(self, event):
        if event.is_directory:
            return
        elif event.event_type == 'created':
            try:
                user = getpass.getuser()
                hostname = socket.gethostname()
                current_datetime = datetime.now()  
                logging.info(f'File {event.src_path} created at {current_datetime}.')
                start_time = time.time()
                time.sleep(3)
                self.process_file(event.src_path)
                end_time = time.time()
                logging.info(f'Time taken: {end_time - start_time:.2f} seconds')
                logging.info('-------------------------------------------')
            except Exception as e:
                logging.error(f"Error processing {event.src_path}: {e}")

    def process_file(self, file_path):
        try:
            # Check if a compressed file with the same name already exists in the archive folder
            archive_folder = r"C:\Users\ALAA\Desktop\compression\archive"
            compressed_file_name = os.path.basename(file_path) + ".zip"

            # If a compressed file with the same name exists, generate a new unique name for the compressed file
            unique_compressed_file_name = self.generate_unique_name(archive_folder, compressed_file_name)
            compressed_file = self.compress_file(file_path, unique_compressed_file_name)

            self.send_notification(compressed_file)
            self.move_to_archive(file_path, compressed_file)
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {e}")

    def generate_unique_name(self, archive_folder, base_name):
        # Generate a unique name for the compressed file
        file_name, extension = os.path.splitext(base_name)
        count = 1
        unique_name = base_name
        while os.path.exists(os.path.join(archive_folder, unique_name)):
            unique_name = f"{file_name}_{count}{extension}"
            count += 1
        return os.path.join(archive_folder, unique_name)

    def send_notification(self, file_path):
        sender_email = "rrapidox@gmail.com"
        sender_password = "s7Gb96A0MXYazn21"
        receiver_email = "rrapidox@gmail.com"
        subject = "Nouveau fichier importé"
        try:
            logging.info("Sending notification email...")
            message = MIMEMultipart()
            message["From"] = sender_email
            message["To"] = receiver_email
            message["Subject"] = subject

            user = getpass.getuser()
            hostname = socket.gethostname()

            body = f"Un nouveau fichier a été importé par {user} sur {hostname}: {os.path.basename(file_path)}"
            message.attach(MIMEText(body, "plain", "utf-8"))

            self.attach_file(message, file_path)

            smtp_server_address = "smtp-relay.brevo.com"
            smtp_port = 587

            smtp_connection = smtplib.SMTP(smtp_server_address, smtp_port)
            smtp_connection.starttls()
            smtp_connection.login(sender_email, sender_password)
            smtp_connection.sendmail(sender_email, receiver_email, message.as_string())

            logging.info("Notification email sent successfully.")
        except SMTPException as e:
            logging.error(f"SMTPException: {e}")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            if "smtp_connection" in locals():
                smtp_connection.quit()

    def compress_file(self, file_path, compressed_file_name):
        try:
            start_time = time.time()
            archive_folder = r"C:\Users\ALAA\Desktop\compression\archive"
            zip_file_path = os.path.join(archive_folder, compressed_file_name)

            with pyzipper.AESZipFile(zip_file_path, 'w', compression=pyzipper.ZIP_DEFLATED,
                                      encryption=pyzipper.WZ_AES) as zipf:
                zipf.setpassword(b'4321')
                zipf.write(file_path, os.path.basename(file_path))

            logging.info(f"File compressed: {zip_file_path}")
            end_time = time.time()
            logging.info(f'Time taken to compress: {end_time - start_time:.2f} seconds')
            return zip_file_path
        except Exception as e:
            logging.error(f"Error compressing file: {e}")
            raise

    def attach_file(self, message, file_path):
        try:
            logging.info(f'Attaching file: {file_path}')
            attachment = open(file_path, "rb")
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(file_path)}")
            message.attach(part)
            attachment.close()
            logging.info(f"File attached: {file_path}")
        except Exception as e:
            logging.error(f"Error attaching file: {e}")

    def move_to_archive(self, original_file_path, compressed_file_path):
        try:
            logging.info(f'Moving file to archive: {original_file_path}')
            archive_folder = r"C:\Users\ALAA\Desktop\compression\archive"
            if not os.path.exists(archive_folder):
                os.makedirs(archive_folder)

            new_path = os.path.join(archive_folder, os.path.basename(compressed_file_path))
            shutil.move(compressed_file_path, new_path)
            logging.info(f"File moved to archive: {new_path}")
        except Exception as e:
            logging.error(f"Error moving file to archive: {e}")

    def calculate_sha256_hash(self, file_path):
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating SHA-256 hash: {e}")
            raise

    def encrypt_hash(self, original_hash):
        encrypted_hash = original_hash.encode("utf-8").hex()
        return encrypted_hash

if __name__ == "__main__":
    event_handler = MyHandler()
    observer = Observer()
    watch_folder = config.get("watch_folder", default_watch_folder)
    observer.schedule(event_handler, watch_folder, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()