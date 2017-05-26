import ctypes

def get_function(library_name, function_name, argtypes, restype=ctypes.c_int, dll_type=ctypes.CDLL):
    library = dll_type(library_name)
    function = getattr(library, function_name)
    function.argtypes = argtypes
    function.restype = restype
    return function
    
def test_get_function():    
    def __sum(numbers):
        length = len(numbers)
        array_type = ctypes.c_int * length
        data_array = array_type(*numbers)
        _sum = get_function("libsumtest.so", "_sum", (ctypes.c_int, ctypes.POINTER(array_type)))        
        result = _sum(ctypes.c_int(length), ctypes.byref(data_array))                      
        return result
    numbers = (1, 2, -3, 4, 5, 6)#range(16)
    answer = sum(numbers)
    _answer = __sum(numbers)
    print _answer, answer
    assert _answer == answer, (_answer, answer)
    
if __name__ == "__main__":
    test_get_function()
    