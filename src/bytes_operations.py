def xor_block(first_in, second_in):
    if len(first_in) != len(second_in):
        raise ValueError("Inputs ought to have same length")
    output = bytearray()
    for i in range(len(first_in)):
        output.append(first_in[i] ^ second_in[i])
    return output

def times_three(input, block_size):
    if len(input) != block_size:
        raise ValueError("Input must have same size as block size")
    output = times_two(input, 8)
    output = xor_block(output, input)
    return output
        

def times_two(input, block_size):
    if len(input) != block_size:
        raise ValueError("Input must have same size as block size")
    output = bytearray(block_size)
    carry = input[0] >> 7
    for i in range(len(input) - 1):
        output[i] = ((input[i] << 1) | (input[i + 1] >> 7)) % 256
    output[-1] = ((input[-1] << 1) ^ (carry * 0x87)) % 256
    if len(output) != block_size:
        raise ValueError("Output's length is incorrect")
    return output


def main():
    # times_two(input, self.cipherBlockSize)
    raise NotImplementedError("Use as package")


if __name__ == "__main__":
    main()
