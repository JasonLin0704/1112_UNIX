with open('./asm.txt', 'r') as f:
    lines = f.readlines()
    for line in lines:
        line = line.strip()
        if line != '': 
            print(line[28:])