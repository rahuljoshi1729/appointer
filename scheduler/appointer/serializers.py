from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import User,Appointment

class UserSignupSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = '__all__'


class appointmentserializer(serializers.ModelSerializer):
    class Meta:
        model=Appointment
        fields=('appointment_date','status','patient_id')


class createappointmentserializer(serializers.ModelSerializer):
    class Meta:
        model=Appointment,User
        fields=('first_name','last_name','specialization','appointment_date','status')


class GetDoctorSerializer(serializers.Serializer):
    email = serializers.EmailField()
    specialization = serializers.CharField() 

    def validate(self, data):
        # Check the account type associated with the given email
        email = data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")

        if not user.is_patient():
            raise serializers.ValidationError("Only patients can access this route.")

        return data
    



class DoctorSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ( 'email', 'first_name', 'last_name', 'specialization')

    def to_representation(self, instance):
        data = super(DoctorSerializer, self).to_representation(instance)
        data['full_name'] = f'{instance.first_name} {instance.last_name}'
        return data







User = get_user_model()

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class passwordresetlink(serializers.Serializer):
    email=serializers.EmailField()
