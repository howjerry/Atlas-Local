BOILING_POINT = 212
MINIMUM_AGE = 18
PASSING_SCORE = 60

def check_temperature(temp):
    if temp > BOILING_POINT:
        return "boiling"

def validate_age(age):
    if age >= MINIMUM_AGE:
        return True
    return False

def check_score(score):
    if score < PASSING_SCORE:
        return "failing"

# Using 0 and 1 is acceptable
def is_empty(items):
    if len(items) == 0:
        return True
    return False
