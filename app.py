from flask import Flask, render_template, request
import os
from analyzer.file_analyzer import analyze_file
import threading, webbrowser

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            uploaded_file.save(filepath)
            result = analyze_file(filepath)
    return render_template('index.html', result=result)

def open_browser():
    webbrowser.open("http://127.0.0.1:5000/")

if __name__ == '__main__':
    threading.Timer(1.25, open_browser).start()
    app.run(debug=True)