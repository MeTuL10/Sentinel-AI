from flask import *  
from flask_wtf import FlaskForm
from wtforms import StringField,SubmitField
# import numpy as np 
from keras.models import load_model
# from sklearn.preprocessing import LabelEncoder
from flask_wtf.csrf import CSRFProtect
import pickle
import pandas as pd
from keras.utils import pad_sequences

def return_prediction_mail(model,user_input): #needs to be updated   
    temp=1
    
def return_prediction_url(model,user_input): #needs to be updated   
    temp=1
    
def return_prediction_sms(model,user_input):    
      sms=[str(user_input['sms'])]
      with open('models\\smstoken.pickle', 'rb') as handle:
            t = pickle.load(handle)
      max_words = 1000
      max_len = 150
      df1=pd.DataFrame(sms,columns=["text"])
      x=df1["text"]
      sequences = t.texts_to_sequences(x)
      sequences_matrix = pad_sequences(sequences,maxlen=max_len)
      output=model.predict(sequences_matrix)
      output=output[0][0]
      if output>0.2:
           return "Spam"
      else:
           return "safe"
    
app = Flask(__name__)  
app.config['SECRET_KEY'] = '6c6722beeac20a0d45f7e977'
CSRFProtect(app)

class smsForm(FlaskForm):
    sms = StringField('sms')
    submit = SubmitField('Predict')

@app.route('/')  
def home():  
      return render_template('index.html')  

@app.route('/Email')
def Email():
      return render_template('Email.html')

@app.route('/URL')
def URL():
      return render_template('URL.html')

@app.route('/Messages', methods=['GET', 'POST'])
def Messages():
      predictor = load_model('models\\sms.keras')
      form = smsForm()
      if form.is_submitted():
            print("submitted")

      if form.validate():
            print("valid")

      print(form.errors)
      if form.validate_on_submit():
            session['sms'] = form.sms
            results= return_prediction_sms(predictor,session)
            return render_template('Messages.html',form=form,results=results)
      return render_template('Messages.html',form=form,results='')
if __name__ == '__main__':  
   app.run(debug = True)