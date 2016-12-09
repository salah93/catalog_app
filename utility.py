import random
import string


def random_string(n=20):
    return ''.join(random.choice(
        string.ascii_letters + string.digits) for x in range(n))
