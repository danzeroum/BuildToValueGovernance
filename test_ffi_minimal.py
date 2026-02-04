
import ctypes

# Load library
lib = ctypes.CDLL('/app/lib/libbuildtovalue_kernel.so')

# Test simple function (no complex structs)
lib.add.argtypes = [ctypes.c_int, ctypes.c_int]
lib.add.restype = ctypes.c_int

result = lib.add(5, 3)
print(f"5 + 3 = {result}")  # Should print 8

# If this works, library is loaded correctly
# If this fails, check LD_LIBRARY_PATH