from flask import Flask, render_template, request
import os
from datetime import datetime
from main import MyHandler
from watchdog.observers import Observer
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
event_handler = MyHandler()
executor = ThreadPoolExecutor(max_workers=5)

@app.route('/')
def index():
    current_datetime = datetime.now()
    archive_folder = r"C:\Users\ALAA\Desktop\compression\archive"
    compressed_files = []

    if os.path.exists(archive_folder) and os.path.isdir(archive_folder):
        compressed_files = [file for file in os.listdir(archive_folder) if file.endswith('.zip')]

    return render_template('index.html', files=compressed_files, current_datetime=current_datetime)

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        search_query = request.form['search_query']
        archive_folder = r"C:\Users\ALAA\Desktop\compression\archive"
        results = [file for file in os.listdir(archive_folder) if search_query in file]
        return render_template('search_results.html', results=results)
    return render_template('search.html')

def handle_created_file(file_path):
    event_handler.on_created(file_path)

@app.route('/traitement-en-parallele')
def traitement_en_parallele():
    watch_folder = r"C:\Users\ALAA\Desktop\compression"
    for filename in os.listdir(watch_folder):
        if filename.endswith('.txt'):
            file_path = os.path.join(watch_folder, filename)
            executor.submit(handle_created_file, file_path)
    return "Traitement de fichiers en parallèle démarré."

if __name__ == '__main__':
    observer = Observer()
    watch_folder = r"C:\Users\ALAA\Desktop\compression"
    observer.schedule(event_handler, watch_folder, recursive=False)
    observer.start()

    app.run(debug=True)