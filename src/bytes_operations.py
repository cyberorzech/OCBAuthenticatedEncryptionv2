def xor_block(first_in, second_in):
    if len(first_in) != len(second_in):
        raise ValueError("Inputs must have same length")
    output = bytearray()
    for i in range(len(first_in)):
        output.append(first_in[i] ^ second_in[i])
    return output

def times_three(input, block_size):
    if len(input) != block_size:
        raise ValueError("Input must have same length as cipher's block size")
    output = times_two(input, block_size)
    output = xor_block(output, input)
    if len(output) != block_size:
        raise ValueError("Output must have same length as cipher's block size")
    return output
        

def times_two(input, block_size):
    blocksize = block_size
    if len(input) != block_size:
        raise ValueError("Input must have same length as cipher's block size")
    output =  bytearray(blocksize)
    carry = input[0] >> 7
    for i in range(len(input) - 1):
        output[i] = ((input[i] << 1) | (input[i + 1] >> 7)) % 256
    output[-1] = ((input[-1] << 1) ^ (carry * 0x87)) % 256
    if len(output) != block_size:
        raise ValueError("Output must have same length as cipher's block size")
    return output


def main():
    # times_two(input, self.cipherBlockSize)
    raise NotImplementedError("Use as package")


if __name__ == "__main__":
    main()
