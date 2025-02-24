class PageTable:
    def __init__(self, num_entries=256):
        self.table = {}
        self.num_entries = num_entries


    def add(self, page_number, frame_number):
        # no replacement algorithm
        self.table[page_number] = frame_number
        self.table[page_number]['valid'] = True
        self.table[page_number]['referenced'] = False
            


    
    