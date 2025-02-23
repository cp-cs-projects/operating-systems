from collections import OrderedDict

class tlb:
    def __init__(self, maxsize=16):
        self.tlb = OrderedDict()
        self.maxsize = maxsize

    def add(self, page_number, frame_number):
        if len(self.tlb) >= self.maxsize:
            self.tlb.popitem(last=False) # FIFO
        self.tlb[page_number] = frame_number

    def lookup(self, page_number):
        if page_number in self.tlb:
            frame_number = self.tlb[page_number]
            # do we move this frame back to the end or preserve the order?
            self.tlb[page_number] = frame_number
            return frame_number
        else:
            return None
        
    def flush(self):
        self.tlb.clear()
        
