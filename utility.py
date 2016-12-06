import random
import string


def random_string():
    return ''.join(random.choice(
        string.ascii_letters + string.digits + string.punctuation) for x in range(20))
