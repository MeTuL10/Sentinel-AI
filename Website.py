from flask import *  
app = Flask(__name__)  
 
@app.route('/')  
def home():  
      return render_template('index.html')  

@app.route('/Email')
def Email():
      return render_template('Email.html')
@app.route('/URL')
def URL():
      return render_template('URL.html')
@app.route('/Messages')
def Messages():
      return render_template('Messages.html')
if __name__ == '__main__':  
   app.run(debug = True)