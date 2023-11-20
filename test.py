import re

patterns = {
        "username": r"\buser(?:name)?=(.*?)(?:&|$)",
        "password": r"(?:password|pwd|pass)=(.*?)(?:&|$)",
        "zip": r"(?:zip|zipcode)=(.*?)(?:&|$)",
        "state": r"(?:state|province|region|st)=(.*?)(?:&|$)",
        "city": r"\bcity=(.*?)(?:&|$)",
        "phone_param": r"(?:phone|telephone|mobile)=(.*?)(?:&|$)",
        "phone": r"\b((\(\d{3}\)\s?|\d{3}[-.\s])?\d{3}[-.\s]\d{4})\b",
        "ssn": r"(?:ssn|social|security|social-security)=(.*?)(?:&|$)",
        "address_ param": r"(?:address|addr)=(.*?)(?:&|$)",
        "birthday": r"(?:birthday|bday)=(.*?)(?:&|$)",
        "last": r"(?:last|surname|lastname|lname)=(.*?)(?:&|$)",
        "first": r"(?:first|firstname|fname)=(.*?)(?:&|$)",
        "email_param": r"(?:email|e-mail|mail)=(.*?)(?:&|$)",
        "email": r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b",
        "credit_card": r"\b((?:\d{4}[- ]?){3}\d{4})\b",
        "credit_card_param": r"(?:credit-card|creditcard)=(.*?)(?:&|$)",
        "ssn": r"\b(\d{3}-\d{2}-\d{4})\b",
        "ssn_param": 
            r"(?:ssn|social|security|social-security)=(.*?)(?:&|$)"
        ,
        "name": r"\b([A-Z][a-z]+ [A-Z][a-z]+)\b",
        "address": 
            r"\b(\d+\s[A-Z][a-zA-Z\s]+,?\s[A-Z]{2}\s\d{5}(-\d{4})?)\b"
        ,
        "cookie": r"(?:Cookie|Set-Cookie):\s?(.*)",
    }

data = "GET http://cs468.cs.uic.edu/submit?firstname=Riccardo&lastname=Strina&birthday=&email=&password=&address=410SMorganStreet&credit-card=&social-security=&phone=&city=Chicago&state=IL&zip=60607"

results = {}
for key, pattern in patterns.items():
    print(key)

    matches = re.compile(pattern).findall(data)
        
    results[key] = matches

print(results)
print(re.compile(r"(?:address|addr)=(.*?)(?:&|$)").findall(data))