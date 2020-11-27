def get_platforms():
    platforms = { "Router": [], "Switch": [], "Firewall": [] }
    with open("supported-platforms.txt", 'r') as f:
        lines = [line.rstrip() for line in f.readlines()]

        i = 0
        while i < len(lines):
            if lines[i] == "Router":
                while lines[i+1]:
                    platforms["Router"].append(lines[i+1])
                    i += 1
            if lines[i] == "Switch":
                while lines[i+1]:
                    platforms["Switch"].append(lines[i+1])
                    i += 1
            if lines[i] == "Firewall":
                while lines[i+1]:
                    platforms["Firewall"].append(lines[i+1])
                    i += 1
            i += 1

    return platforms

