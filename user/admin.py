from django.contrib import admin
from .models import NewUser, EncounterDaily, Gender, Customer, CustomerAgreement, Promoter, EncounterExit, CustomerSample, Sample, CustomerGIID, GIID, CustomerContact, Contact, Agreement, Group, PromotersGroup, ClaimType
# Register your models here.
admin.site.register(NewUser)
admin.site.register(EncounterDaily)
admin.site.register(Gender)
admin.site.register(Customer)
admin.site.register(CustomerAgreement)
admin.site.register(Promoter)
admin.site.register(EncounterExit)
admin.site.register(CustomerSample)
admin.site.register(Sample)
admin.site.register(CustomerGIID)
admin.site.register(GIID)
admin.site.register(CustomerContact)
admin.site.register(Contact)
admin.site.register(Agreement)
admin.site.register(Group)
admin.site.register(PromotersGroup)
admin.site.register(ClaimType)
