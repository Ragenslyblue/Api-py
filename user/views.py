from multiprocessing import context
from urllib import response
from django.shortcuts import render
from django.urls import is_valid_path
from django.views.decorators.csrf import csrf_exempt
from pymysql import Date
from rest_framework.parsers import JSONParser
from django.http.response import JsonResponse
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.permissions import SAFE_METHODS, IsAdminUser, IsAuthenticated, BasePermission, AllowAny
from user import serializer
import jwt
import datetime
from rest_framework.authtoken.models import Token
from user.models import EncounterDaily, Gender, Customer, CustomerAgreement, NewUser, Promoter, EncounterExit, CustomerSample, Sample, CustomerGIID, GIID, CustomerContact, Contact, Agreement, Group, PromotersGroup, ClaimType
from user.serializer import UserSerializer, EncounterDailySerializer, GenderSerializer, CustomerSerializer, CustomerAgreementSerializer, PromoterSerializer, EncounterExitSerializer, CustomerSampleSerializer, SampleSerializer, CustomerGIIDSerializer, GIIDSerializer, CustomerContactSerializer, ContactSerializer, AgreementSerializer, GroupSerializer, PromotersGroupSerializer, ClaimTypeSerializer

# Create your views here.

# custom permission


class EncounterDailyUserWritePermission(BasePermission):
    message = 'Editing encounter daily is restricted to the author only'

    def has_object_permission(self, request, view, obj):

        if request.method in SAFE_METHODS:
            return True

        return obj.PromoterID == request.user


# viewset


class EncounterDailyView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = EncounterDaily.objects.all()
    serializer_class = EncounterDailySerializer


class GenderView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Gender.objects.all()
    serializer_class = GenderSerializer


class CustomerView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer


class CustomerAgreementView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = CustomerAgreement.objects.all()
    serializer_class = CustomerAgreementSerializer


class NewUserView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = NewUser.objects.all()
    serializer_class = UserSerializer


class PromoterView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Promoter.objects.all()
    serializer_class = PromoterSerializer


class EncounterExitView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = EncounterExit.objects.all()
    serializer_class = EncounterExitSerializer


class CustomerSampleView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = CustomerSample.objects.all()
    serializer_class = CustomerSampleSerializer


class SampleView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Sample.objects.all()
    serializer_class = SampleSerializer


class CustomerGIIDView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = CustomerGIID.objects.all()
    serializer_class = CustomerGIIDSerializer


class GIIDView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = GIID.objects.all()
    serializer_class = GIIDSerializer


class CustomerContactView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = CustomerContact.objects.all()
    serializer_class = CustomerContactSerializer


class ContactView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer


class AgreementView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Agreement.objects.all()
    serializer_class = AgreementSerializer


class GroupView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Group.objects.all()
    serializer_class = GroupSerializer


class PromotersGroupView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = PromotersGroup.objects.all()
    serializer_class = PromotersGroupSerializer


class ClaimTypeView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = ClaimType.objects.all()
    serializer_class = ClaimTypeSerializer


@csrf_exempt
def EncounterDailyAPI(request, id=0):
    if request.method == 'GET':
        encounterDaily = EncounterDaily.objects.all()
        encounterdaily_serializer = EncounterDailySerializer(
            encounterDaily, many=True)
        return JsonResponse(encounterdaily_serializer.data, safe=False)
    elif request.method == 'POST':
        encounterDaily_data = JSONParser().parse(request)
        encounterdaily_serializer = EncounterDailySerializer(
            data=encounterDaily_data)
        if encounterdaily_serializer.is_valid():
            encounterdaily_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        encounterDaily_data = JSONParser().parse(request)
        encounterDaily = EncounterDaily.objects.get(
            id=encounterDaily_data['id'])
        encounterdaily_serializer = EncounterDailySerializer(
            encounterDaily, data=encounterDaily_data)
        if encounterdaily_serializer.is_valid():
            encounterdaily_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        encounterDaily = EncounterDaily.objects.get(id=id)
        encounterDaily.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def GenderAPI(request, id=0):
    if request.method == 'GET':
        gender = Gender.objects.all()
        gender_serializer = GenderSerializer(
            gender, many=True)
        return JsonResponse(gender_serializer.data, safe=False)
    elif request.method == 'POST':
        gender_data = JSONParser().parse(request)
        gender_serializer = GenderSerializer(
            data=gender_data)
        if gender_serializer.is_valid():
            gender_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        gender_data = JSONParser().parse(request)
        gender = Gender.objects.get(
            id=gender_data['id'])
        gender_serializer = GenderSerializer(
            gender, data=gender_data)
        if gender_serializer.is_valid():
            gender_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        gender = Gender.objects.get(id=id)
        gender.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def CustomerAPI(request, id=0):
    if request.method == 'GET':
        customer = Customer.objects.all()
        customer_serializer = CustomerSerializer(
            customer, many=True)
        return JsonResponse(customer_serializer.data, safe=False)
    elif request.method == 'POST':
        customer_data = JSONParser().parse(request)
        customer_serializer = CustomerSerializer(
            data=customer_data)
        if customer_serializer.is_valid():
            customer_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        customer_data = JSONParser().parse(request)
        customer = Customer.objects.get(
            id=customer_data['id'])
        customer_serializer = CustomerSerializer(
            customer, data=customer_data)
        if customer_serializer.is_valid():
            customer_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        customer = Customer.objects.get(id=id)
        customer.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def CustomerAgreementAPI(request, id=0):
    if request.method == 'GET':
        customer = CustomerAgreement.objects.all()
        customerAgreement_serializer = CustomerAgreementSerializer(
            customer, many=True)
        return JsonResponse(customerAgreement_serializer.data, safe=False)
    elif request.method == 'POST':
        customerAgreement_data = JSONParser().parse(request)
        customerAgreement_serializer = CustomerAgreementSerializer(
            data=customerAgreement_data)
        if customerAgreement_serializer.is_valid():
            customerAgreement_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        customerAgreement_data = JSONParser().parse(request)
        customer = CustomerAgreement.objects.get(
            id=customerAgreement_data['id'])
        customerAgreement_serializer = CustomerAgreementSerializer(
            customer, data=customerAgreement_data)
        if customerAgreement_serializer.is_valid():
            customerAgreement_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        customer = CustomerAgreement.objects.get(id=id)
        customer.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def PromoterAPI(request, id=0):
    if request.method == 'GET':
        promoter = Promoter.objects.all()
        promoter_serializer = PromoterSerializer(
            promoter, many=True)
        return JsonResponse(promoter_serializer.data, safe=False)
    elif request.method == 'POST':
        promoter_data = JSONParser().parse(request)
        promoter_serializer = PromoterSerializer(
            data=promoter_data)
        if promoter_serializer.is_valid():
            promoter_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        promoter_data = JSONParser().parse(request)
        promoter = Promoter.objects.get(
            id=promoter_data['id'])
        promoter_serializer = PromoterSerializer(
            promoter, data=promoter_data)
        if promoter_serializer.is_valid():
            promoter_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        promoter = Promoter.objects.get(id=id)
        promoter.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def EncounterExitAPI(request, id=0):
    if request.method == 'GET':
        encounterExit = EncounterExit.objects.all()
        encounterExit_serializer = EncounterExitSerializer(
            encounterExit, many=True)
        return JsonResponse(encounterExit_serializer.data, safe=False)
    elif request.method == 'POST':
        encounterExit_data = JSONParser().parse(request)
        encounterExit_serializer = EncounterExitSerializer(
            data=encounterExit_data)
        if encounterExit_serializer.is_valid():
            encounterExit_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        encounterExit_data = JSONParser().parse(request)
        encounterExit = EncounterExit.objects.get(
            id=encounterExit_data['id'])
        encounterExit_serializer = EncounterExitSerializer(
            encounterExit, data=encounterExit_data)
        if encounterExit_serializer.is_valid():
            encounterExit_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        encounterExit = EncounterExit.objects.get(id=id)
        encounterExit.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def CustomerSampelAPI(request, id=0):
    if request.method == 'GET':
        customerSample = CustomerSample.objects.all()
        customerSample_serializer = CustomerSampleSerializer(
            customerSample, many=True)
        return JsonResponse(customerSample_serializer.data, safe=False)
    elif request.method == 'POST':
        customerSample_data = JSONParser().parse(request)
        customerSample_serializer = CustomerSampleSerializer(
            data=customerSample_data)
        if customerSample_serializer.is_valid():
            customerSample_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        customerSample_data = JSONParser().parse(request)
        customerSample = CustomerSample.objects.get(
            id=customerSample_data['id'])
        customerSample_serializer = CustomerSampleSerializer(
            customerSample, data=customerSample_data)
        if customerSample_serializer.is_valid():
            customerSample_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        customerSample = CustomerSample.objects.get(id=id)
        customerSample.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def SampleAPI(request, id=0):
    if request.method == 'GET':
        sample = Sample.objects.all()
        sample_serializer = SampleSerializer(
            sample, many=True)
        return JsonResponse(sample_serializer.data, safe=False)
    elif request.method == 'POST':
        sample_data = JSONParser().parse(request)
        sample_serializer = SampleSerializer(
            data=sample_data)
        if sample_serializer.is_valid():
            sample_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        sample_data = JSONParser().parse(request)
        sample = Sample.objects.get(
            id=sample_data['id'])
        sample_serializer = SampleSerializer(
            sample, data=sample_data)
        if sample_serializer.is_valid():
            sample_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        sample = Sample.objects.get(id=id)
        sample.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def CustomerGIIDAPI(request, id=0):
    if request.method == 'GET':
        customerGIID = CustomerGIID.objects.all()
        customerGIID_serializer = CustomerGIIDSerializer(
            customerGIID, many=True)
        return JsonResponse(customerGIID_serializer.data, safe=False)
    elif request.method == 'POST':
        customerGIID_data = JSONParser().parse(request)
        customerGIID_serializer = CustomerGIIDSerializer(
            data=customerGIID_data)
        if customerGIID_serializer.is_valid():
            customerGIID_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        customerGIID_data = JSONParser().parse(request)
        customerGIID = CustomerGIID.objects.get(
            id=customerGIID_data['id'])
        customerGIID_serializer = CustomerGIIDSerializer(
            customerGIID, data=customerGIID_data)
        if customerGIID_serializer.is_valid():
            customerGIID_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        customerGIID = CustomerGIID.objects.get(id=id)
        customerGIID.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def GIIDAPI(request, id=0):
    if request.method == 'GET':
        GIIDdata = GIID.objects.all()
        GIID_serializer = GIIDSerializer(
            GIIDdata, many=True)
        return JsonResponse(GIID_serializer.data, safe=False)
    elif request.method == 'POST':
        GIID_data = JSONParser().parse(request)
        GIID_serializer = GIIDSerializer(
            data=GIID_data)
        if GIID_serializer.is_valid():
            GIID_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        GIID_data = JSONParser().parse(request)
        GIIDdata = GIID.objects.get(
            id=GIID_data['id'])
        GIID_serializer = GIIDSerializer(
            GIIDdata, data=GIID_data)
        if GIID_serializer.is_valid():
            GIID_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        GIIDdata = GIID.objects.get(id=id)
        GIIDdata.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def CustomerContactAPI(request, id=0):
    if request.method == 'GET':
        customerContact = CustomerContact.objects.all()
        customerContact_serializer = CustomerContactSerializer(
            customerContact, many=True)
        return JsonResponse(customerContact_serializer.data, safe=False)
    elif request.method == 'POST':
        customerContact_data = JSONParser().parse(request)
        customerContact_serializer = CustomerContactSerializer(
            data=customerContact_data)
        if customerContact_serializer.is_valid():
            customerContact_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        customerContact_data = JSONParser().parse(request)
        customerContact = CustomerContact.objects.get(
            id=customerContact_data['id'])
        customerContact_serializer = CustomerContactSerializer(
            customerContact, data=customerContact_data)
        if customerContact_serializer.is_valid():
            customerContact_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        customerContact = CustomerContact.objects.get(id=id)
        customerContact.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def ContactAPI(request, id=0):
    if request.method == 'GET':
        contact = Contact.objects.all()
        contact_serializer = ContactSerializer(
            contact, many=True)
        return JsonResponse(contact_serializer.data, safe=False)
    elif request.method == 'POST':
        contact_data = JSONParser().parse(request)
        contact_serializer = ContactSerializer(
            data=contact_data)
        if contact_serializer.is_valid():
            contact_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        contact_data = JSONParser().parse(request)
        contact = Contact.objects.get(
            id=contact_data['id'])
        contact_serializer = ContactSerializer(
            contact, data=contact_data)
        if contact_serializer.is_valid():
            contact_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        contact = Contact.objects.get(id=id)
        contact.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def AgreementAPI(request, id=0):
    if request.method == 'GET':
        agreement = Agreement.objects.all()
        agreement_serializer = AgreementSerializer(
            agreement, many=True)
        return JsonResponse(agreement_serializer.data, safe=False)
    elif request.method == 'POST':
        agreement_data = JSONParser().parse(request)
        agreement_serializer = AgreementSerializer(
            data=agreement_data)
        if agreement_serializer.is_valid():
            agreement_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        agreement_data = JSONParser().parse(request)
        agreement = Agreement.objects.get(
            id=agreement_data['id'])
        agreement_serializer = AgreementSerializer(
            agreement, data=agreement_data)
        if agreement_serializer.is_valid():
            agreement_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        agreement = Agreement.objects.get(id=id)
        agreement.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def GroupAPI(request, id=0):
    if request.method == 'GET':
        group = Group.objects.all()
        group_serializer = GroupSerializer(
            group, many=True)
        return JsonResponse(group_serializer.data, safe=False)
    elif request.method == 'POST':
        group_data = JSONParser().parse(request)
        group_serializer = GroupSerializer(
            data=group_data)
        if group_serializer.is_valid():
            group_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        group_data = JSONParser().parse(request)
        group = Group.objects.get(
            id=group_data['id'])
        group_serializer = GroupSerializer(
            group, data=group_data)
        if group_serializer.is_valid():
            group_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        group = Group.objects.get(id=id)
        group.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def PromotersGroupAPI(request, id=0):
    if request.method == 'GET':
        promotersGroup = PromotersGroup.objects.all()
        promoters_serializer = PromotersGroupSerializer(
            promotersGroup, many=True)
        return JsonResponse(promoters_serializer.data, safe=False)
    elif request.method == 'POST':
        promoters_data = JSONParser().parse(request)
        promoters_serializer = PromotersGroupSerializer(
            data=promoters_data)
        if promoters_serializer.is_valid():
            promoters_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        promoters_data = JSONParser().parse(request)
        promotersGroup = PromotersGroup.objects.get(
            id=promoters_data['id'])
        promoters_serializer = PromotersGroupSerializer(
            promotersGroup, data=promoters_data)
        if promoters_serializer.is_valid():
            promoters_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        promotersGroup = PromotersGroup.objects.get(id=id)
        promotersGroup.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def ClaimTypeAPI(request, id=0):
    if request.method == 'GET':
        claimtype = ClaimType.objects.all()
        claimtype_serializer = ClaimTypeSerializer(
            claimtype, many=True)
        return JsonResponse(claimtype_serializer.data, safe=False)
    elif request.method == 'POST':
        claimType_data = JSONParser().parse(request)
        claimtype_serializer = ClaimTypeSerializer(
            data=claimType_data)
        if claimtype_serializer.is_valid():
            claimtype_serializer.save()
            return JsonResponse("Added successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        claimType_data = JSONParser().parse(request)
        claimtype = ClaimType.objects.get(
            id=claimType_data['id'])
        claimtype_serializer = ClaimTypeSerializer(
            claimtype, data=claimType_data)
        if claimtype_serializer.is_valid():
            claimtype_serializer.save()
            return JsonResponse("Updated successfully", safe=False)
        return JsonResponse("Failed to update")
    elif request.method == 'DELETE':
        claimtype = ClaimType.objects.get(id=id)
        claimtype.delete()
        return JsonResponse("Deleted successfully", safe=False)

# views for user registration


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            newuser = serializer.save()
            if newuser:
                return Response(status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# logout/blacklist view


# class BlacklistTokenView(APIView):
#     permission_classes = [AllowAny]

#     def post(self, request)
#         try:


# def post(self, request):
#     serializer = UserSerializer(data=request.data)
#     serializer.is_valid(raise_exception=True)
#     serializer.save()
#     return Response(serializer.data)

# views for user login


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']

        user = NewUser.objects.filter(email=email).first()

        if user is None:
            raise AuthenticationFailed('User not found!')

        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password!')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, 'secret',
                           algorithm='HS256')
        response = Response()
        response.set_cookie(key='token', value=token, httponly=True)
        response.data = {
            'token': token
        }
        return response


class GetUserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('token')

        if not token:
            raise AuthenticationFailed('Unauthenticated!')

        try:
            payload = jwt.decode(token, 'secret',
                                 algorithms=['HS256'])

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

        user = NewUser.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)

        return Response(serializer.data)


class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('token')

        response.data = {
            'message': 'successfully log out!'
        }

        return response


class TotalEncounterPerGroupView(APIView):
    def get_queryset(self):
        return EncounterDaily.objects.filter(PromoterID=1)
