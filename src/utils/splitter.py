class Splitter:
    def __init__(self, limit: int, packetSize: int):
        if packetSize <= 0:
            raise ValueError("packetSize must be greater than 0")
        self.packetSize = packetSize
        if limit < -1:
            raise ValueError("limit must be -1 or greater")
        self.limit = limit

    def split(self, lines: list[str]) -> list[list[str]]:
        if lines is None:
            raise ValueError("lines is None")

        outputList: list[list[str]] = []
        max_end = (len(lines) // self.packetSize) * self.packetSize
        for i in range(0, max_end, self.packetSize):
            if len(outputList) >= self.limit != -1:
                break
            outputList.append(lines[i:i + self.packetSize])
        return outputList