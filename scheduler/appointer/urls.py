from django.contrib import admin
from django.urls import include, path
from .views import my_view,my_recaptha,signup,UserLoginView,PasswordResetRequestView,PasswordResetView,ShowAppointmentsView,GetDoctorsView,delete_doctor,Mark,create_appointment

urlpatterns=[
  # path('',my_view,name="my_page"),
   #path('form/',my_recaptha,name="my_page"),
   path('signup/',signup,name="signup"),
   path('login/', UserLoginView.as_view(), name='login'),
   path('password/reset/',PasswordResetRequestView.as_view(),name='reset_link'),
  path('password/reset/<token>/',PasswordResetView.as_view(),name="password_reset"),
  path('showappointment/',ShowAppointmentsView.as_view(),name='appointments'),
  path('getdoctor/',GetDoctorsView.as_view(),name='get_doctor'),
  path('delete/',delete_doctor,name="delete_doctor"),
  path('doctor/completed/',Mark.as_view(),name="MARK"),
  path('appoint/create/',create_appointment,name=("create")),

]