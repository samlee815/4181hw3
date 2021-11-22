from django.test import Client
from django.db import connection
from django.test import TestCase
from django.test.testcases import _AssertTemplateUsedContext
from LegacySite.models import User, Product, Card

# Create your tests here.
# Please view: https://docs.djangoproject.com/en/3.2/topics/testing/overview/

# Sample check that you can access website

# 1- Write the test confirming XSS vulnerability is fixed
# send a get request with a parameter that contains a script that will redirect to google.com
# upon success fix, the script will not appear on the page rendered
class XSSTest(TestCase):
    def setUp(self):
        product = Product.objects.create(product_id='1',product_name="NYU Apparel Card",
            product_image_path = "/images/product_1.jpg",recommended_price = 95,description = "Use this card to buy NYU Clothing!")

    def test_xss(self):
        d = Client()
        response = d.get("/buy",{"director" : "<script type=\"text/javascript\">window.location.href = \"http://www.google.com\";</script>"})
        #print(response.content)
        #assert(response.status_code == 200)
        self.assertTemplateUsed(response, 'item-single.html')
        self.assertNotContains(response,"<script type=\"text/javascript\">window.location.href = \"http://www.google.com\";</script>")


# 2- Write the test confirming CSRF vulnerability is fixed
class CSRFTest(TestCase):
    def test_csrf(self):
        d = Client(enforce_csrf_checks=True)
        response = d.post("/gift/0",{"username" : "am","amount" : "1082"})
        # upon success fix, the response will give error code 403
        assert(response.status_code == 403)

# 3- Write the test confirming SQL Injection attack is fixed
class SQLInjectionTest(TestCase):

    def setUp(self):
        user = User.objects.create(id = 6,
            username = 'admin',
            password = '000000000000000000000000000078d2$18821d89de11ab18488fdc0a01f1ddf4d290e198b0f80cd4974fc031dc2615a3')
        user = User.objects.create(id = 7,
            username = 'am',
            password = '000000000000000000000000000078d2$7010123db2fe8cb37a3c9b36e33b54c901c857a46a6786657fbf9cae5b0a17f7')
        product = Product.objects.create(product_id='1',product_name="NYU Apparel Card",
            product_image_path = "/images/product_1.jpg",recommended_price = 95,description = "Use this card to buy NYU Clothing!")
        card = Card.objects.create(id = 1,amount = 93,data = bytes("sda",'utf-8'),
                fp = "some",used =False,product_id = '1',user_id = 7)

    def test_sql_injection(self):
        #upload the gift card with sql_injection attack
        file = open('./sql_injection.gftcrd', 'r', encoding='utf-8')
        d = Client()
        #login to the service to prevent potential crash
        d.login(username = "am",password = "am")
        response = d.post("/use",{"card_supplied" : True,"card_fname" : "sql_injection.gftcrd","card_data" :file})
        # upon success fix, the response will not show the password of admin
        assert(response.status_code == 200)
        #we should not see the password of admin
        self.assertNotContains(response,"000000000000000000000000000078d2$18821d89de11ab18488fdc0a01f1ddf4d290e198b0f80cd4974fc031dc2615a3")