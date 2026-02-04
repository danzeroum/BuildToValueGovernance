lib = ctypes.CDLL('/app/lib/libbuildtovalue_kernel.so')

lib.scan_for_evidence.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),  # input_ptr
    ctypes.c_size_t,                  # input_len
    ctypes.POINTER(TechnicalEvidence), # output_ptr
]
lib.scan_for_evidence.restype = ctypes.c_int32