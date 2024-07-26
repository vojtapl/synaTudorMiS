import pickle
import struct
import hashlib

with open('./data.pkl', 'rb') as fle:
    data = pickle.load(fle)

print(f'len of data: {len(data)}')

    part1 = data[:16]
    print(part1.hex())

    # Version verification
    (
        version1,
        version2,
    ) = struct.unpack('<BB', data[:2])
    assert version1 == 1 and version2 == 0

    (
        some_size1,
        encrypted_data_size,
        encrypted_hash_len,
    ) = struct.unpack('<III', data[4:4+4*3])
    print(f'some_size1: {some_size1}')
    print(f'encrypted_data_size: {encrypted_data_size}')
    print(f'encrypted_hash_len is {encrypted_hash_len}')

    some_len = 0x10 + some_size1 + encrypted_data_size
    data1_hash = hashlib.sha256(data[:some_len])

    decrypted_hash = CryptUnprotectData(data1_hash)
    assert len(decrypted_hash) == 0x20

    # verify HMAC hash
    assert decrypted_hash == data1_hash

    if encrypted_data_size != 0:
        data2_offset = 0x10 + some_size1
        decrypted_data = CryptUnprotectData(data[data2_offset:data2_offset+encrypted_data_size])

    result = b''
    if some_size1 != 0:
        result += data[0x10:0x10+some_size1]
    result += decrypted_data
return result
