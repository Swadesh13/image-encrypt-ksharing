from main import *
from timeit import timeit

print(timeit("main()", globals=globals(), number=10))
