# Easy — Missing Type Annotations
# Expected: TYPE003 on greet, compute, transform (3 diagnostics)

def greet(name):
    return f"Hello, {name}!"


def compute(x, y):
    return x + y


def transform(data):
    return [item.upper() for item in data]


# This one has an annotation — should NOT trigger TYPE003.
def proper_function(x: int) -> int:
    return x * 2
