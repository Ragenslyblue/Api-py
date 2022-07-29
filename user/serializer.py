from dataclasses import field
from rest_framework import serializers
from user.models import NewUser, EncounterDaily, Gender, Customer, CustomerAgreement, Promoter, EncounterExit, CustomerSample, Sample, CustomerGIID, GIID, CustomerContact, Contact, Agreement, Group, PromotersGroup, ClaimType


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewUser
        fields = ['id', 'email', 'user_name', 'first_name',
                  'start_date', 'is_staff', 'is_active', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


class EncounterDailySerializer(serializers.ModelSerializer):
    class Meta:
        model = EncounterDaily
        fields = '__all__'


class GenderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Gender
        fields = '__all__'


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'


class CustomerAgreementSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerAgreement
        fields = '__all__'


class PromoterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Promoter
        fields = '__all__'


class EncounterExitSerializer(serializers.ModelSerializer):
    class Meta:
        model = EncounterExit
        fields = '__all__'


class CustomerSampleSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerSample
        fields = '__all__'


class SampleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sample
        fields = '__all__'


class CustomerGIIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerGIID
        fields = '__all__'


class GIIDSerializer(serializers.ModelSerializer):
    class Meta:
        model = GIID
        fields = '__all__'


class CustomerContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerContact
        fields = '__all__'


class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = '__all__'


class AgreementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Agreement
        fields = '__all__'


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'


class PromotersGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = PromotersGroup
        fields = '__all__'


class ClaimTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClaimType
        fields = '__all__'
