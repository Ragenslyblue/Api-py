"""core URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, re_path, path
from user.views import RegisterView, AgreementView, ClaimTypeView, ContactView, CustomerAgreementView, CustomerContactView, CustomerGIIDView, CustomerSampleView, CustomerView, EncounterDailyView, EncounterExitView, GIIDView, GenderView, GroupView, NewUserView, PromoterView, PromotersGroupView, SampleView
from rest_framework import routers
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
# EncounterDaily, Gender, Customer, CustomerAgreement, NewUser, Promoter, EncounterExit, CustomerSample, Sample, CustomerGIID, GIID, CustomerContact, Contact, Agreement, Group, PromotersGroup, ClaimType

route = routers.DefaultRouter()
route.register("encounterdaily", EncounterDailyView,
               basename='encounterView')
route.register("gender", GenderView,
               basename='genderView')
route.register("customer", CustomerView,
               basename='customerView')
route.register("customerAgreement", CustomerAgreementView,
               basename='customerAgreementView')
route.register("user", NewUserView,
               basename='userView')
route.register("promoter", PromoterView,
               basename='promoterView')
route.register("encounterExit", EncounterExitView,
               basename='encounterExitview')
route.register("customerSample", CustomerSampleView,
               basename='customerSampleView')
route.register("sample", SampleView,
               basename='sampelView')
route.register("customerGIID", CustomerGIIDView,
               basename='customerGIIDView')
route.register("GIID", GIIDView,
               basename='GIIDView')
route.register("customerContract", CustomerContactView,
               basename='customerContractView')
route.register("contract", ContactView,
               basename='contractview')
route.register("agreement", AgreementView,
               basename='agreementview')
route.register("group", GroupView,
               basename='groupView')
route.register("promotersGroup", PromotersGroupView,
               basename='promotersGroupView')
route.register("claimType", ClaimTypeView,
               basename='claimTypeview')
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(route.urls)),
    path('api/user/register', RegisterView.as_view(),
         name='register'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

]
