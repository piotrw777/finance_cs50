def has_digit(str):
    digits={'0','1','2','3','4','5','6','7','8','9'}
    for char in str:
        if char in digits:
            return True
    return False

def has_upper_letter(str):
    for char in str:
        if char.isupper():
            return True
    return False

def has_lower_letter(str):
    for char in str:
        if char.islower():
            return True
    return False

def has_special_symbol(str):
    specials={'!','@','#','$','%','^','&','*','(', \
')','-','_','+','=',';',':','\"','\'',',','.','/',\
'<','>','?','[',']','|','\\','`'}
    for char in str:
        if char in specials:
            return True
    return False

has_special_symbol("a")