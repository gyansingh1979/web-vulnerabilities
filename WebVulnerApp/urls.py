from django.urls import path

from . import views

urlpatterns = [path("index.html", views.index, name="index"),
               path("AdminLogin.html", views.AdminLogin, name="AdminLogin"),	      
               path("AdminLoginAction", views.AdminLoginAction, name="AdminLoginAction"),
               path("RegisterAction", views.RegisterAction, name="RegisterAction"),
               path("Register.html", views.Register, name="Register"),
               path("UserLogin.html", views.UserLogin, name="UserLogin"),	      
               path("UserLoginAction", views.UserLoginAction, name="UserLoginAction"),
	       path("ViewUsers", views.ViewUsers, name="ViewUsers"),	      
               path("ViewCSRF", views.ViewCSRF, name="ViewCSRF"),
	       path("ViewPost", views.ViewPost, name="ViewPost"),	      
               path("ViewGet", views.ViewGet, name="ViewGet"),
	       path("ActivateUserAction", views.ActivateUserAction, name="ActivateUserAction"),
	       path("RunCsrf", views.RunCsrf, name="RunCsrf"),
	       path("RunCsrfAction", views.RunCsrfAction, name="RunCsrfAction"),
	       path("RunMitch", views.RunMitch, name="RunMitch"),
	       path("RunML", views.RunML, name="RunML"),	      
]
