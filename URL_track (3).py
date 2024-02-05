import tkinter
from turtle import update
from pywinauto import Application
from urllib.parse import urlparse,urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn import metrics
from tkinter import *
from turtle import onclick

urls = []

def havingIP(url):
    try:
      ipaddress.ip_address(url)
      ip = 1
    except:
      ip = 0
    return ip
def haveAtSign(url):
    if "@" in url:
      at = 1    
    else:
      at = 0    
    return at
def getLength(url):
    if len(url) < 54:
      length = 0            
    else:
      length = 1            
    return length
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
      if pos > 7:
        return 1
      else:
        return 0
    else:
      return 0
def prefixSuffix(url):
      if '-' in urlparse(url).netloc:
          return 1           
      else:
          return 0
def web_traffic(url):
    try:
      #Filling the whitespaces in the URL if any
      url = urllib.parse.quote(url)
      rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
          "REACH")['RANK']
      rank = int(rank)
    except TypeError:
          return 1
    if rank <100000:
      return 1
    else:
      return 0
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
      try:
        creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
        expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
      except:
        return 1
    if ((expiration_date is None) or (creation_date is None)):
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 1
    else:
      ageofdomain = abs((expiration_date - creation_date).days)
      if ((ageofdomain/30) < 6):
        age = 1
      else:
        age = 0
    return age
def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1
def mouseOver(response): 
    if response == "" :
      return 1
    else:
      if re.findall("<script>.+onmouseover.+</script>", response.text):
        return 1
      else:
        return 0
def rightClick(response):
    if response == "":
      return 1
    else:
      if re.findall(r"event.button ?== ?2", response.text):
        return 0
      else:
        return 1
def featureExtraction(url,label):

    features = []
    features.append(havingIP(url))
    features.append(getLength(url))
    features.append(haveAtSign(url))
    features.append(prefixSuffix(url))
    features.append(redirection(url))
    
    try:
      response = requests.get(url)
    except:
      response = ""
    dns = 0
    try:
      domain_name = whois.whois(urlparse(url).netloc)
    except:
      dns = 1
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(iframe(response))
    features.append(domainAge(domain_name))
    features.append(dns)
    features.append(web_traffic(url))
    return features

def check_url(url):
  df = pd.read_csv("D://URL_pp.csv")

  x = df.iloc[:,:11]
  y = df.iloc[:,-1:]


  x_train,x_test,y_train,y_test = train_test_split(x,y,test_size=0.3)
  x_train.shape



  lr = LogisticRegression(multi_class='ovr')
  gnb = GaussianNB()
  knn = KNeighborsClassifier(n_neighbors=3)

  lr.fit(x_train,y_train)
  gnb.fit(x_train,y_train)
  knn.fit(x_train,y_train)

  y_pred_log = lr.predict_proba(x_train).argmax(axis=1)
  y_pred_NB = gnb.predict(x_train)
  y_pred_knn = knn.predict(x_train)



  final_votes = []

  for i in range(len(y_pred_log)):
      sum_class = y_pred_log[i] + y_pred_NB[i] + y_pred_knn[i]
      if sum_class >=2:
          final_votes.append(1)
      else:
          final_votes.append(0)
          
  mse_vote = metrics.mean_squared_error(y_train, final_votes)

  features = featureExtraction(url,0)
  data = [features]

  df1 = pd.DataFrame(data,columns=['having_IP_Address','URL_Length','having_At_Symbol','Prefix_Suffix','Redirect','on_mouseover','RightClick','Iframe','age_of_domain','DNSRecord','web_traffic'])

  y_pred_log = lr.predict_proba(df1).argmax(axis=1)
  y_pred_NB = gnb.predict(df1)
  y_pred_knn = knn.predict(df1)

  final_votes = []

  for i in range(len(y_pred_log)):
      sum_class = y_pred_log[i] + y_pred_NB[i] + y_pred_knn[i]
      if sum_class >=2:
          final_votes.append(1)
      else:
          final_votes.append(0)
          
  if final_votes[0]==1:
      print("Phishy URL")

  else:
      print("Nothing to worry")

def update(url):
  urls.append(url)


while True:
  app = Application(backend='uia')
  app.connect(title_re=".*Chrome.*")
  dlg = app.top_window()
  url = dlg.child_window(title="Address and search bar", control_type="Edit").get_value()
  print(url)
  check_url(url)