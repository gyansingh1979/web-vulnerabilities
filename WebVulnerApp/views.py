from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
import os
import pickle
import pymysql
from django.core.files.storage import FileSystemStorage
from datetime import date
from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from sklearn.model_selection import train_test_split
import Bolt
from Bolt.RunCSRF import *
from datetime import datetime
import json

global uname, csrf_list, attack, url_list, url

def ViewPost(request):
    if request.method == 'GET':
        dataset = pd.read_csv("Dataset/features_matrix.csv")
        dataset = dataset[['numOfParams', 'numOfBools', 'numOfIds','numOfBlobs','reqLen', 'isPOST']].values
        output = '<table border=1><tr>'
        output+='<td><font size="" color="black">numOfParams</td>'
        output+='<td><font size="" color="black">numOfBools</td>'
        output+='<td><font size="" color="black">numOfIds</td>'
        output+='<td><font size="" color="black">numOfBlobs</td>'
        output+='<td><font size="" color="black">reqLen</td>'
        output+='<td><font size="" color="black">isPOST</td></tr>'
        for i in range(len(dataset)):
            output += "<tr>"
            for j in range(len(dataset[i])):
                output+='<td><font size="" color="black">'+str(dataset[i,j])+'</td>'
            output += "</tr>"
        output += "</table></br></br></br>"    
        context= {'data': output}
        return render(request, 'AdminScreen.html', context)

def ViewGet(request):
    if request.method == 'GET':
        dataset = pd.read_csv("Dataset/features_matrix.csv")
        dataset = dataset[['numOfParams', 'numOfBools', 'numOfIds','numOfBlobs','reqLen', 'isGET']].values
        output = '<table border=1><tr>'
        output+='<td><font size="" color="black">numOfParams</td>'
        output+='<td><font size="" color="black">numOfBools</td>'
        output+='<td><font size="" color="black">numOfIds</td>'
        output+='<td><font size="" color="black">numOfBlobs</td>'
        output+='<td><font size="" color="black">reqLen</td>'
        output+='<td><font size="" color="black">isGET</td></tr>'
        for i in range(len(dataset)):
            output += "<tr>"
            for j in range(len(dataset[i])):
                output+='<td><font size="" color="black">'+str(dataset[i,j])+'</td>'
            output += "</tr>"
        output += "</table></br></br></br>"    
        context= {'data': output}
        return render(request, 'AdminScreen.html', context)    

def ViewCSRF(request):
    if request.method == 'GET':
        global csrf_list, attack, url_list, url
        today = str(datetime.now())
        output = '<table border=1><tr>'
        output+='<td><font size="" color="black">S.No</td>'
        output+='<td><font size="" color="black">Regex Name</td>'
        output+='<td><font size="" color="black">CSRF Hashes</td>'
        output+='<td><font size="" color="black">URL Names</td>'
        output+='<td><font size="" color="black">Date Time</td></tr>'
        j = 0
        for i in range(len(csrf_list)):
            cl = csrf_list[i]
            output+='<tr><td><font size="" color="black">'+str(i + 1)+'</td>'
            output+='<td><font size="" color="black">'+str(cl[0])+'</td>'
            output+='<td><font size="" color="black">'+str(cl[1])+'</td>'
            if j < len(url_list):
                output+='<td><font size="" color="black">'+str(url_list[j])+'</td>'
                j += 1
            else:
                j = 0
                output+='<td><font size="" color="black">'+str(url_list[j])+'</td>'
                j += 1
            output+='<td><font size="" color="black">'+str(today)+'</td></tr>'
        output+='<tr><td><font size="" color="black">'+attack+'</td>'    
        output += "</table></br></br></br>"    
        context= {'data': output}
        return render(request, 'AdminScreen.html', context) 

def RunCsrf(request):
    if request.method == 'GET':
        return render(request, 'RunCsrf.html', {})

def RunCsrfAction(request):
    if request.method == 'POST':
        global uname, csrf_list, attack, url_list, url
        url = request.POST.get('t1', False)
        depth = request.POST.get('t2', False)
        url_list, csrf_list, attack = getVulner(url, int(depth.strip()))
        today = str(datetime.now())
        output = '<table border=1><tr>'
        output+='<td><font size="" color="black">S.No</td>'
        output+='<td><font size="" color="black">Regex Name</td>'
        output+='<td><font size="" color="black">CSRF Hashes</td>'
        output+='<td><font size="" color="black">URL Names</td>'
        output+='<td><font size="" color="black">Date Time</td></tr>'
        j = 0
        for i in range(len(csrf_list)):
            cl = csrf_list[i]
            output+='<tr><td><font size="" color="black">'+str(i + 1)+'</td>'
            output+='<td><font size="" color="black">'+str(cl[0])+'</td>'
            output+='<td><font size="" color="black">'+str(cl[1])+'</td>'
            if j < len(url_list):
                output+='<td><font size="" color="black">'+str(url_list[j])+'</td>'
                j += 1
            else:
                j = 0
                output+='<td><font size="" color="black">'+str(url_list[j])+'</td>'
                j += 1
            output+='<td><font size="" color="black">'+str(today)+'</td></tr>'
        output+='<tr><td><font size="" color="black">'+attack+'</td>'    
        output += "</table></br></br></br>"    
        context= {'data': output}
        return render(request, 'UserScreen.html', context)    
        
def RunMitch(request):
    if request.method == 'GET':
        output = '<table border=1><tr>'
        output+='<td><font size="" color="black">Mitch Process</td></tr>'
        f = open('Dataset/dataset.json')
        data = json.load(f)
        for i in data:
            keys = i.keys()
            data = i['data']
            website = i['website']
            i = 0
            for x in data:
                output+='<tr><td><font size="" color="black">'+str(x)+'</td></tr>'
        output += "</table></br></br></br>"    
        context= {'data': output}
        return render(request, 'UserScreen.html', context)  
        
def RunML(request):
    if request.method == 'GET':
        dataset = pd.read_csv("Dataset/features_matrix.csv")
        X = dataset[['numOfParams', 'numOfBools', 'numOfIds','numOfBlobs','reqLen']].values
        Y = dataset[['isPOST']].values.ravel()
        Y1 = dataset[['isGET']].values.ravel()
        X_train,X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=0)
        rf = RandomForestClassifier()
        rf.fit(X_train, y_train)
        predict = rf.predict(X_test)
        algorithm = "POST"
        p = precision_score(y_test, predict,average='macro') * 100
        r = recall_score(y_test, predict,average='macro') * 100
        f = f1_score(y_test, predict,average='macro') * 100
        a = accuracy_score(y_test,predict)*100

        output = '<table border=1><tr>'
        output+='<td><font size="" color="black">Method</td>'
        output+='<td><font size="" color="black">Accuracy</td>'
        output+='<td><font size="" color="black">Precision</td>'
        output+='<td><font size="" color="black">Recall</td>'
        output+='<td><font size="" color="black">F1 Score</td></tr>'
        output+='<tr><td><font size="" color="black">POST</td>'
        output+='<td><font size="" color="black">'+str(a)+'</td>'
        output+='<td><font size="" color="black">'+str(p)+'</td>'
        output+='<td><font size="" color="black">'+str(r)+'</td>'
        output+='<td><font size="" color="black">'+str(f)+'</td></tr>'

        X_train,X_test, y_train, y_test = train_test_split(X, Y1, test_size=0.2, random_state=0)
        rf = RandomForestClassifier()
        rf.fit(X_train, y_train)
        predict = rf.predict(X_test)
        algorithm = "POST"
        p = precision_score(y_test, predict,average='macro') * 100
        r = recall_score(y_test, predict,average='macro') * 100
        f = f1_score(y_test, predict,average='macro') * 100
        a = accuracy_score(y_test,predict)*100
        output+='<tr><td><font size="" color="black">GET</td>'
        output+='<td><font size="" color="black">'+str(a)+'</td>'
        output+='<td><font size="" color="black">'+str(p)+'</td>'
        output+='<td><font size="" color="black">'+str(r)+'</td>'
        output+='<td><font size="" color="black">'+str(f)+'</td></tr>'
        context= {'data': output}
        return render(request, 'UserScreen.html', context)  

def ActivateUserAction(request):
    if request.method == 'GET':
        global uname
        user = request.GET.get('t1', False)
        status = request.GET.get('t2', False)        
        db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'webvulner',charset='utf8')
        db_cursor = db_connection.cursor()
        student_sql_query = "update account_register set status='"+status+"' where username='"+user+"' and status='Pending'"
        db_cursor.execute(student_sql_query)
        db_connection.commit()
        status = "User Account status updated to "+status
        context= {'data': status}
        return render(request, 'AdminScreen.html', context)

def ViewUsers(request):
    if request.method == 'GET':
        output = '<table border=1><tr>'
        output+='<td><font size="" color="black">Username</td>'
        output+='<td><font size="" color="black">Password</td>'
        output+='<td><font size="" color="black">Contact No</td>'
        output+='<td><font size="" color="black">Email ID</td>'
        output+='<td><font size="" color="black">Address</td>'
        output+='<td><font size="" color="black">Status</td>'
        output+='<td><font size="" color="black">Approve User</td></tr>'
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'webvulner',charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select * FROM account_register")
            rows = cur.fetchall()
            for row in rows:
                output+='<tr><td><font size="" color="black">'+str(row[0])+'</td>'
                output+='<td><font size="" color="black">'+str(row[1])+'</td>'
                output+='<td><font size="" color="black">'+str(row[2])+'</td>'
                output+='<td><font size="" color="black">'+str(row[3])+'</td>'
                output+='<td><font size="" color="black">'+str(row[4])+'</td>'
                output+='<td><font size="" color="black">'+str(row[5])+'</td>'
                if row[5] == 'Pending':
                    output+='<td><a href=\'ActivateUserAction?t1='+str(row[0])+'&t2=Approved\'><font size=3 color=black>Click Here to Approved</font></a></td></tr>'
                else:
                    output+='<td><font size="" color="black">Done</td></tr>'
        output += "</table><br/><br/><br/><br/>"
        context= {'data':output}
        return render(request, 'AdminScreen.html', context)

def UserLogin(request):
    if request.method == 'GET':
       return render(request, 'UserLogin.html', {})   

def AdminLogin(request):
    if request.method == 'GET':
       return render(request, 'AdminLogin.html', {})    

def Register(request):
    if request.method == 'GET':
       return render(request, 'Register.html', {})

def index(request):
    if request.method == 'GET':
       return render(request, 'index.html', {})

def AdminLoginAction(request):
    if request.method == 'POST':
        global uname
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        if username == 'admin' and password == 'admin':
            context= {'data':'welcome '+username}
            return render(request, 'AdminScreen.html', context)
        else:
            context= {'data':'login failed'}
            return render(request, 'AdminLogin.html', context)

def UserLoginAction(request):
    if request.method == 'POST':
        global uname, pin
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        index = 0
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'webvulner',charset='utf8')
        with con:    
            cur = con.cursor()
            cur.execute("select username, password FROM account_register where status='Approved'")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == username and password == row[1]:
                    uname = username
                    index = 1
                    break		
        if index == 1:
            context= {'data':'welcome '+username}
            return render(request, 'UserScreen.html', context)
        else:
            context= {'data':'login failed'}
            return render(request, 'UserLogin.html', context)        
    

def RegisterAction(request):
    if request.method == 'POST':
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        email = request.POST.get('t4', False)
        address = request.POST.get('t5', False)
        
        status = "none"
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'webvulner',charset='utf8')
        with con:    
            cur = con.cursor()
            cur.execute("select username FROM account_register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == username:
                    status = "Username already exists"
                    break
        if status == "none":
            db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'webvulner',charset='utf8')
            db_cursor = db_connection.cursor()
            student_sql_query = "INSERT INTO account_register(username,password,contact_no,email,address,status) VALUES('"+username+"','"+password+"','"+contact+"','"+email+"','"+address+"','Pending')"
            db_cursor.execute(student_sql_query)
            db_connection.commit()
            print(db_cursor.rowcount, "Record Inserted")
            if db_cursor.rowcount == 1:
                status = "Account created you can login with "+username
        context= {'data': status}
        return render(request, 'Register.html', context)

