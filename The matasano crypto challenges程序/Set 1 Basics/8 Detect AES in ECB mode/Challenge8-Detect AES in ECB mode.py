
f = open('Challenge8.txt','r')

for line in f:
        data = line.rstrip().decode("hex") #rstrip() throws off '\n'
        blocks = dict()

        assert len(data) % 16 == 0
        for i in range(0, len(data), 16):
                cur_block = data[i:i+16]
                if cur_block in blocks:
                        blocks[cur_block] = blocks[cur_block] + 1
                else:
                        blocks[cur_block] = 1

        if max(blocks.values()) > 1:
                print "ECB-encrypted text is :"
                print line.rstrip()
                break