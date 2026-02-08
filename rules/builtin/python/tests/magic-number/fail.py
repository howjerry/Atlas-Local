def check_temperature(temp):
    if temp > 212:
        return "boiling"

def validate_age(age):
    if age >= 18:
        return True
    return False

def check_score(score):
    if score < 60:
        return "failing"
