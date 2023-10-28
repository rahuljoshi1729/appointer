
import json
import urllib.request  # Use urllib.request for making HTTP requests
from django.shortcuts import render, redirect
from django.contrib import messages
from .form import SignupForm,loginform
from .models import User,PasswordReset,Appointment,loginmodel
from django.conf import settings
from django.contrib.auth.hashers import make_password


from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserLoginSerializer,passwordresetlink,appointmentserializer,createappointmentserializer,GetDoctorSerializer,DoctorSerializer
from django.contrib.auth import authenticate

from django.core.exceptions import ObjectDoesNotExist
from django.utils.http import urlsafe_base64_encode
from django.core.mail import send_mail
from .token import custom_token_generator
import datetime

from django.contrib.auth import login

from django.utils.http import urlsafe_base64_decode
from django.utils.http import urlsafe_base64_encode
import json
import uuid


from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view

from django.views.decorators.csrf import csrf_protect
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone

def my_view(request):
    return render(request, 'index.html')

def my_recaptha(request):
    return render(request, 'form.html')

def signup(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():

            ''' Begin reCAPTCHA validation '''
            recaptcha_response = request.POST.get('g-recaptcha-response')
            url = 'https://www.google.com/recaptcha/api/siteverify'
            values = {
                'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
                'response': recaptcha_response
            }
            data = urllib.parse.urlencode(values).encode()  # Encode the data
            req = urllib.request.Request(url, data)
            response = urllib.request.urlopen(req)
            result = json.load(response)
            ''' End reCAPTCHA validation '''

            if result['success']:
                email = form.cleaned_data['email']

                # Check if the email already exists in the User table
                if User.objects.filter(email=email).exists():
                    messages.error(request, 'Email already exists. Please use a different email.')
                else:
                    password = form.cleaned_data['password']
                    salt = form.cleaned_data['salt']
                    salted_password = f"{salt}${password}"
                    hashed_password = make_password(password)

                    # Create the User object with the hashed password
                    user = form.save(commit=False)
                    user.password = hashed_password
                    user.save()
                    
                    messages.success(request, 'Registration successful!')
                    
                    # Redirect to the desired page after successful registration
                  #  return redirect('login')  Change 'login' to your actual login page name
            else:
                messages.error(request, 'Invalid reCAPTCHA. Please try again.')

    else:
        form = SignupForm()

    return render(request, 'signup.html', {'form': form})


User = get_user_model()

class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']

            # Check if the email exists in the database
            try:
                user = User.objects.get(email=email)
                print(password)
                print(email)
            except User.DoesNotExist:
                return Response({'detail': 'Email does not exist'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if the password is correct
            #user = authenticate(request, email=user.email)
            if(email==user.email):
                token=str(uuid.uuid4())
                login_=loginmodel(email=email,token=token,user=user)
                login_.isverified=True
                login_.save()

                """ if user is not None:
                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)"""
                return Response({'access_token': token}, status=status.HTTP_200_OK) 
            
            return Response({'detail': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({'detail': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)






User = get_user_model()

class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = passwordresetlink(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']

            # Use filter to check if the email exists
            users = User.objects.filter(email=email)
            if not users.exists():
                return Response({'detail': 'Email does not exist'}, status=status.HTTP_404_NOT_FOUND)

            for user in users:
                token=str(uuid.uuid4())
                password_reset=PasswordReset(token=token,user=user)
                password_reset.save()

                # Constructing the reset URL with the unique token
                reset_url = f"http://127.0.0.1:8000/api/password/reset/{token}/"  

                subject = 'Password Reset Request'
                message = f'You can reset your password by following this link: {reset_url}'

                send_mail(subject, message, 'your_email@example.com', [user.email])

            return Response({'detail': 'Password reset email sent successfully'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
# input ==> body: email


class PasswordResetView(APIView):
    def post(self, request, token):
        
        try:

            # Check if the token exists in the PasswordReset table and is verified
            password_reset = PasswordReset.objects.get(token=token)
            
            user = password_reset.user

            #implement that if new password is same as that of previous password give error

            # Change the user's password
            new_password = request.data.get('new_password')
            new_password = make_password(new_password)
            user.set_password(new_password)
            user.save()

            # Mark the PasswordReset record as used
            password_reset.delete()

            return Response({'detail': 'Password reset successfully'}, status=status.HTTP_200_OK)
        except PasswordReset.DoesNotExist:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST) 
        
#input token in parameter and new_password in body


User = get_user_model()

class ShowAppointmentsView(APIView):
    def get(self, request):
        email = request.query_params.get('email', None)
        if not email:
            return Response({'detail': 'Email query parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            if user.account_type != 'Patient':
                return Response({'detail': 'User is not a patient'}, status=status.HTTP_400_BAD_REQUEST)

            # Fetch appointments for the patient with the specified id and "scheduled" status
            appointments = Appointment.objects.filter(patient_id=user.id ,status='scheduled')
            if not appointments:
                
                return Response({'error': 'No scheduled appointments found for this patient'}, status=status.HTTP_404_NOT_FOUND)

            # Serialize the appointments and return them
            serializer = appointmentserializer(appointments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'detail': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
        









class GetDoctorsView(APIView):
    def post(self, request):
        data = request.data

        # Check if email is provided in the JSON data
        email = data.get('email', None)
        if not email:
            return Response({'detail': 'Email is required in the request data.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the email corresponds to a patient
        try:
            patient = User.objects.get(email=email, account_type='Patient')
        except User.DoesNotExist:
            return Response({'detail': 'The provided email does not belong to a patient.'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if specialization is provided in the JSON data
        specialization = data.get('specialization', None)
        if not specialization:
            return Response({'detail': 'Specialization is required in the request data.'}, status=status.HTTP_400_BAD_REQUEST)

        # Get all doctors with the provided specialization
        doctors = User.objects.filter(account_type='Doctor', specialization=specialization)

        # Serialize the list of doctors using the DoctorSerializer
        serializer = DoctorSerializer(doctors, many=True)

        # Return the list of doctors in the response
        return Response(serializer.data, status=status.HTTP_200_OK)     




@csrf_exempt
def delete_doctor(request):
    if request.method == 'DELETE':
        admin_id = request.GET.get('id', None)
        doctor_email = request.GET.get('doctor_email', None)
        
        if not admin_id:
            return JsonResponse({'detail': 'Admin ID is required in the query parameters.'}, status=400)
        if not doctor_email:
            return JsonResponse({'detail': 'Doctor Email is required in the query parameters.'}, status=400)
        
        try:
            # Check if the user making the request is an admin
            admin = User.objects.get(id=admin_id)
            if admin.account_type != 'Admin':
                return JsonResponse({'detail': 'Only administrators can perform this action.'}, status=403)

            # Retrieve the doctor based on the provided email and delete
            doctor = User.objects.get(email=doctor_email, account_type='Doctor')
            doctor.delete()

            return JsonResponse({'detail': f'Doctor with email {doctor_email} has been deleted.'}, status=204)
        except User.DoesNotExist:
            return JsonResponse({'detail': 'User not found with the provided email.'}, status=404)
    else:
        return JsonResponse({'detail': 'Invalid request method.'}, status=405)


#http://127.0.0.1:8000/admin/delete/?id=1&doctor_email=doctor@example.com


class Mark(APIView):
    def patch(self, request):

        user_email = request.data.get('email', None)

        if not user_email:
            return Response({'detail': 'Email is required in the request body.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=user_email)


            if user.account_type!='Doctor':
                return Response({'detail': 'Only doctors can mark appointments as completed.'}, status=status.HTTP_403_FORBIDDEN)

            # appointment ID 
            appointment_id = request.query_params.get('appointment_id', None)

            if not appointment_id:
                return Response({'detail': 'Appointment ID is required in the query parameters.'}, status=status.HTTP_400_BAD_REQUEST)

    
            appointment = Appointment.objects.get(id=appointment_id)

            # Mark the status as "completed"
            appointment.status = 'completed'
            appointment.save()

            return Response({'detail': f'Appointment {appointment_id} has been marked as completed.'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'detail': 'User not found with the provided email.'}, status=status.HTTP_404_NOT_FOUND)
        except Appointment.DoesNotExist:
            return Response({'detail': 'Appointment not found with the provided ID for the current doctor.'}, status=status.HTTP_404_NOT_FOUND)





@csrf_exempt
@require_POST
def create_appointment(request):

    # Get the doctor_id from the query parameters
    doctorid = request.GET.get("doctor_id",None)
    print(doctorid)

    # Check if the provided doctor_id is a valid doctor's id
    try:
        doctor = User.objects.get(id=doctorid)
    except User.DoesNotExist:
        return JsonResponse({"error": "Invalid id."}, status=400)

    # Ensure that the doctor is a Doctor
    if doctor.account_type != "Doctor":
        return JsonResponse({"error": "The specified doctor_id does not correspond to a Doctor."}, status=400)

    # Get patient's email from the request body
    patient_email = request.GET.get("email",None)
    

    # Check if the provided email is a valid patient's email
    try:
        patient = User.objects.get(email=patient_email)
        print(patient)
    except User.DoesNotExist:
        return JsonResponse({"error": "user does not exist."}, status=400)

    # Check if the patient is a patient
    if patient.account_type !="Patient":
        return JsonResponse({"error": "The specified email does not correspond to a Patient."}, status=400)

    # Check if the patient's email is verified using loginmodel table
    try:
        login_entry = loginmodel.objects.get(email=patient_email)
        if not login_entry.isverified:
            return JsonResponse({"error": "Patient's email is not verified."}, status=400)
    except loginmodel.DoesNotExist:
        return JsonResponse({"error": "Patient's email is not found in the loginmodel table."}, status=400)
 
    
    appointment = Appointment(status="scheduled",doctor_id=doctorid,patient_id=patient.id, appointment_date=timezone.now())
    appointment.save()


    subject = 'Your Appointment Details'
    message = f'Hello {patient.first_name},\n\nYou have scheduled an appointment with {doctor.first_name} {doctor.last_name} on {appointment.appointment_date}.\n\nAppointment Details:\n- Date and Time: {appointment.appointment_date}\n- Doctor: {doctor.first_name} {doctor.last_name}\n\nPlease arrive on time for your appointment.\n\nThank you!'
    from_email = '9271rsil@gmail.com'  # Use the email you configured in settings.py
    recipient_list = [patient.email]

    try:
        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
    except Exception as e:
        return JsonResponse({"error": "Failed to send the appointment confirmation email."}, status=500)

    

    return JsonResponse({"message": "Appointment created successfully."}, status=200)
