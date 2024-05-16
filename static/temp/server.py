from flask import Flask, render_template, request, redirect, session, flash, send_file, send_from_directory,  make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import zipfile
import shutil
from werkzeug.utils import secure_filename
from datetime import datetime
from scan import analyze_code
import os
import json

os.makedirs('static', exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)
os.makedirs('static/img', exist_ok=True)
os.makedirs('static/source_code', exist_ok=True)
os.makedirs('static/temp', exist_ok=True)

app = Flask(__name__)

app.secret_key = 'super secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shield.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMP_FOLDER'] = 'static/temp'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = ['zip']

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)



def allowed_file(filename):
    ext = '.' in filename and filename.rsplit('.', 1)[1].lower()
    print(ext)
    return ext in app.config['ALLOWED_EXTENSIONS']

def unzip_src_code(zip_file, folder):
    temp_folder = app.config['TEMP_FOLDER']                                        # temp folder                                                 # create source code folder if not exists
    os.makedirs(temp_folder, exist_ok=True)
    os.makedirs(os.path.join(temp_folder, "".join(folder.split())), exist_ok=True)                  # create folder for source code    
    # extract all files
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall(os.path.join(temp_folder, folder))
    return os.path.join(temp_folder, folder)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

# register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if User.query.filter_by(username=username).first():
            flash('User already exists!', 'danger')
            return redirect('/register')
        if User.query.filter_by(email=email).first():
            flash('Email already exists!', 'danger')
            return redirect('/register')
        user = User(username=username, password=password, email=email)
        db.session.add(user)
        db.session.commit()
        flash('User successfully registered!', 'success')
        return redirect('/login')
    return render_template('register.html')

# login
@app.route('/login', methods=['GET', 'POST'])
def login():
    # flash('Please login to continue!', 'info')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)
            flash('User successfully logged in!', 'success')
            return redirect('/dashboard')
        flash('Invalid credentials!', 'danger')
        return redirect('/login')
    return render_template('login.html')

# logout
@app.route('/logout')
def logout():
    logout_user()
    flash('User successfully logged out!', 'success')
    return redirect('/')

# dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    source_codes = SourceCode.query.filter_by(user_id=current_user.id).all()
    print(len(source_codes))
    return render_template('dashboard.html', source_codes=source_codes)

# upload zip file
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        name = request.form['name']
        zip_file = request.files['zip_file']
        if zip_file and allowed_file(zip_file.filename):
            try:
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                zip_file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(zip_file.filename))
                zip_file.save(zip_file_path)
                source_code = SourceCode(name=name, user_id=current_user.id, zip_file=zip_file_path)
                db.session.add(source_code)
                db.session.commit()
                flash('Source code uploaded successfully!', 'info')
                return redirect('/dashboard')
            except Exception as e:
                print(e)
                flash('Invalid file!', 'danger')
                return redirect('/upload')
        else:
            flash('Invalid file!', 'danger')
            return redirect('/upload')
    return render_template('upload.html')

@app.route('/analyse/<int:srcid>', methods=['GET'])
def analyse_files(srcid):
    source_code = SourceCode.query.get(srcid)
    if not source_code:
        flash('Source code not found!', 'danger')
        return redirect('/dashboard')
    folder ="".join((source_code.name.split()))
    zip_file = source_code.zip_file
    extracted_path = unzip_src_code(zip_file, folder)
    files = os.listdir(extracted_path)
    for file in files:
        if file.endswith('.py'):
            print(f'path = {os.path.join(extracted_path, file)}')
            report_path = analyze_code(os.path.join(extracted_path, file))
            report = Report(source_code_id=srcid, report_path=report_path)
            db.session.add(report)
            db.session.commit()
    source_code.status = 'Completed'
    db.session.commit()
    flash('Analysis completed successfully!', 'success')
    return json.dumps({'status': 'success'})
    
# download report
@app.route('/download/<int:id>')
@login_required
def download(id):
    try:
        report = Report.query.get(id)
        return send_file(report.report_path, as_attachment=True)
    except Exception as e:
        print(e)
        flash('Report not found!', 'danger')
        return redirect('/dashboard')

# delete source code
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    try:
        source_code = SourceCode.query.get(id)
        db.session.delete(source_code)
        db.session.commit()
        # delete zip file
        os.remove(source_code.zip_file)
        # delete report files
        reports = Report.query.filter_by(source_code_id=id).all()
        for report in reports:
            try:os.remove(report.report_path)
            except:pass
            db.session.delete(report)
        db.session.commit()
        flash('Source code deleted successfully!', 'success')
        return redirect('/dashboard')
    except Exception as e:
        print(e)
        flash('Source code not found!', 'danger')
        return redirect('/dashboard')

# delete report
@app.route('/delete_report/<int:id>')
@login_required
def delete_report(id):
    try:
        report = Report.query.get(id)
        db.session.delete(report)
        db.session.commit()
        os.remove(report.report_path)
        flash('Report deleted successfully!', 'success')
    except Exception as e:
        print(e)
        flash('Report not found!', 'danger')
    return redirect('/dashboard')

# view source code files
@app.route('/view/<int:id>')
@login_required
def view(id):
    try:
        source_code = SourceCode.query.get(id)
        files = os.listdir(os.path.join(app.config['SRC_FOLDER'], source_code.name))
        # name, size, type, created, modified, accessed, is_dir
        file_details = []
        for file in files:
            file_path = os.path.join(app.config['SRC_FOLDER'], source_code.name, file)
            file_stat = os.stat(file_path)
            file_details.append({
                'name': file,
                'size': file_stat.st_size,
                'type': 'File' if os.path.isfile(file_path) else 'Directory',
                'created': datetime.fromtimestamp(file_stat.st_ctime),
                'modified': datetime.fromtimestamp(file_stat.st_mtime),
                'accessed': datetime.fromtimestamp(file_stat.st_atime),
                'is_dir': os.path.isdir(file_path)
            })
        return render_template('view.html', files=file_details, name=source_code.name,)
    except Exception as e:
        print(e)
        flash('Source code not found!', 'danger')
        return redirect('/dashboard')

# view report
@app.route('/report/<int:srcid>')
@login_required
def view_report(srcid):
    try:
        source_code = SourceCode.query.get(srcid)
        reports = Report.query.filter_by(source_code_id=srcid).all() 
        issues = ""
        names = ""
        for report in reports:
            filename = report.report_path.split('\\')[-1]
            report.filename = filename
            with open(report.report_path, 'r') as f:
                report.content = f.readlines()[2:-4]
                report.issue_count = len(report.content)
                issues+=f"{report.issue_count},"
                names+=f"{filename},"

        return render_template('report.html', 
                               reports=reports, 
                               source_code=source_code, 
                               srcid=srcid,
                               issues=issues, 
                               names=names)
    except Exception as e:
        print(e)
        flash('Report not found!', 'danger')
        return redirect('/dashboard')
        

    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', port=8000, debug=True)
 