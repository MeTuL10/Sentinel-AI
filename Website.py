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
import re
from urllib.parse import urlparse
from googlesearch import search
from tld import get_tld
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import re
import nltk
from nltk.corpus import stopwords
import contractions
import string
import json
def urlprocess(df): # feature extraction of url
      def having_ip_address(url):
            match = re.search(
                  '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                  '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                  '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
                  '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
            if match:
                  return 1
            else:
                  return 0
      df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
      
      def abnormal_url(url):
            hostname = urlparse(url).hostname
            hostname = str(hostname)
            match = re.search(hostname, url)
            if match:
                  return 1
            else:
                  return 0
      df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))

      def google_index(url):
            site = search(url, 5)
            return 1 if site else 0
      df['google_index'] = df['url'].apply(lambda i: google_index(i))
      
      def count_dot(url):
            count_dot = url.count('.')
            return count_dot
      df['count.'] = df['url'].apply(lambda i: count_dot(i))
      
      def count_www(url):
            url.count('www')
            return url.count('www')
      df['count-www'] = df['url'].apply(lambda i: count_www(i))
      
      def count_atrate(url): 
            return url.count('@')
      df['count@'] = df['url'].apply(lambda i: count_atrate(i))
      
      def no_of_dir(url):
            urldir = urlparse(url).path
            return urldir.count('/')
      df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))

      def no_of_embed(url):
            urldir = urlparse(url).path
            return urldir.count('//')
      df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))
      
      def shortening_service(url):
            match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',url)
            if match:
                  return 1
            else:
                  return 0
      df['short_url'] = df['url'].apply(lambda i: shortening_service(i))

      def count_https(url):
            return url.count('https')
      df['count-https'] = df['url'].apply(lambda i : count_https(i))
      
      def count_http(url):
            return url.count('http')
      df['count-http'] = df['url'].apply(lambda i : count_http(i))

      def count_per(url):
            return url.count('%')
      df['count%'] = df['url'].apply(lambda i : count_per(i))
      
      def count_ques(url):
            return url.count('?')
      df['count?'] = df['url'].apply(lambda i: count_ques(i))
      
      def count_hyphen(url):
            return url.count('-')
      df['count-'] = df['url'].apply(lambda i: count_hyphen(i))
      
      def count_equal(url):
            return url.count('=')
      df['count='] = df['url'].apply(lambda i: count_equal(i))
      
      def url_length(url):
            return len(str(url))
      df['url_length'] = df['url'].apply(lambda i: url_length(i))

      def hostname_length(url):
            return len(urlparse(url).netloc)
      df['hostname_length'] = df['url'].apply(lambda i: hostname_length(i))

      def suspicious_words(url):
            match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
            if match:
                  return 1
            else:
                  return 0
      df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
      
      def digit_count(url):
            digits = 0
            for i in url:
                  if i.isnumeric():
                        digits = digits + 1
            return digits
      df['count-digits']= df['url'].apply(lambda i: digit_count(i))
      
      def letter_count(url):
            letters = 0
            for i in url:
                  if i.isalpha():
                        letters = letters + 1
            return letters
      df['count-letters']= df['url'].apply(lambda i: letter_count(i))

      def fd_length(url):
            urlpath= urlparse(url).path
            try:
                  return len(urlpath.split('/')[1])
            except:
                  return 0
      df['fd_length'] = df['url'].apply(lambda i: fd_length(i))
      df['tld'] = df['url'].apply(lambda i: get_tld(i,fail_silently=True))

      def tld_length(tld):
            try:
              return len(tld)
            except:
                  return -1
      df['tld_length'] = df['tld'].apply(lambda i: tld_length(i))
      # df = df.drop("tld",1)
      return df

def url_model_train(): #traing the random forest model for url prediction
      df=pd.read_csv('dataset\\malicious_phish.csv')
      df=urlprocess(df)
      #array(['benign', 'defacement', 'malware', 'phishing']
      mapd={'benign':0,'defacement':1,'malware':2,'phishing':3}
      df['type_code']=df['type'].apply(lambda i: mapd[i])
      X = df[['use_of_ip','abnormal_url', 'count.', 'count-www', 'count@','count_dir', 'count_embed_domian', 'short_url', 'count-https','count-http', 
            'count%', 'count?', 'count-', 'count=', 'url_length','hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits','count-letters']]
      y = df['type_code']
      X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2,shuffle=True, random_state=5)
      
      rf = RandomForestClassifier(n_estimators=100,max_features='sqrt')
      rf.fit(X_train,y_train)
      return rf
rf=url_model_train()

english_punctuations = string.punctuation
punctuations_list = english_punctuations
stop_words = stopwords.words('english')
def preprocess(data):
      def small(data):
            return data.lower()
      def cleaning_numbers(data):
            return re.sub('[0-9]+', '', data)
      def cleaning_contractions(text):
            text=text.split()
            corrected=[]
            for word in text:
                  corrected.append(contractions.fix(word))
            return " ".join(corrected)
      def cleaning_punctuations(text):
            return re.sub(re.compile("["+punctuations_list+"‼️’]")," ",text)
      def cleaning_stopwords(data):
            words = data.split()
            filtered_words = [word for word in words if word not in stop_words]
            filtered_text = ' '.join(filtered_words)
            return filtered_text
      temp=small(data)
      temp=cleaning_numbers(temp)
      temp=cleaning_contractions(temp)
      temp=cleaning_punctuations(temp)
      temp=cleaning_stopwords(temp)
      return temp

def custom_model(data):
      data=preprocess(data)
      data=data.split()
      f=open("models\\cyberattacks.json")
      model=json.load(f)
      attacks=model.keys()
      predictions=dict()
      for i in attacks:
            for j in data:

                  predictions[i]=predictions.get(i,0)+model[i].get(j,0)
      predictions=dict(sorted(predictions.items(),key=lambda x: x[1], reverse=True))
      temp=list(predictions.keys())
      return(temp[0])

def return_prediction_mail(model,user_input):  
      mail=[str(user_input['mail'])]
      with open('models\\mailtoken.pickle', 'rb') as handle:
            t = pickle.load(handle)
      maxlen1=5916
      df1=pd.DataFrame(mail,columns=["text"])
      x=df1["text"]
      sequences = t.texts_to_sequences(x)
      sequences_matrix = pad_sequences(sequences,maxlen=maxlen1)
      output=model.predict(sequences_matrix)
      output=output[0][0]
      if output>0.2:
           return "Spam,"+custom_model(str(user_input['mail']))
      else:
           return "safe,"+custom_model(str(user_input['mail']))
    
def return_prediction_url(model,user_input):   
      map=['benign', 'defacement', 'malware', 'phishing']
      url=[str(user_input['url'])]
      df=pd.DataFrame(url,columns=['url'])
      df=urlprocess(df)
      X = df[['use_of_ip','abnormal_url', 'count.', 'count-www', 'count@','count_dir', 'count_embed_domian', 'short_url', 'count-https','count-http', 
            'count%', 'count?', 'count-', 'count=', 'url_length','hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits','count-letters']]
      y=model.predict(X)
      return map[y[0]]
 
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
           return "Spam,"+custom_model(str(user_input['sms']))
      else:
           return "safe,"+custom_model(str(user_input['sms']))
    
app = Flask(__name__)  
app.config['SECRET_KEY'] = '6c6722beeac20a0d45f7e977'
CSRFProtect(app)

class mailForm(FlaskForm):
    mail = StringField('mail')
    submit = SubmitField('Predict')

class smsForm(FlaskForm):
    sms = StringField('sms')
    submit = SubmitField('Predict')

class urlForm(FlaskForm):
    url = StringField('url')
    submit = SubmitField('Predict')

@app.route('/')  
def home():  
      return render_template('index.html')  

@app.route('/Email', methods=['GET', 'POST'])
def Email():
      predictor = load_model('models\\mail.keras')
      form = mailForm()
      if form.is_submitted():
            print("submitted")

      if form.validate():
            print("valid")

      print(form.errors)
      if form.validate_on_submit():
            session['mail'] = form.mail
            results= return_prediction_mail(predictor,session)
            return render_template('Email.html',form=form,results=results)
      return render_template('Email.html',form=form,results='')

@app.route('/URL', methods=['GET', 'POST'])
def URL():
      form = urlForm()
      if form.is_submitted():
            print("submitted")

      if form.validate():
            print("valid")

      print(form.errors)
      if form.validate_on_submit():
            session['url'] = form.url
            results= return_prediction_url(rf,session)
            return render_template('URL.html',form=form,results=results)
      return render_template('URL.html',form=form,results='')

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