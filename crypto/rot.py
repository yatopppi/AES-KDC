from aes import round_key, bytes_to_matrix

def rot_word(word):
    return word[1:] + word[:1]

data = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]

data = bytes_to_matrix(data)

print(data)