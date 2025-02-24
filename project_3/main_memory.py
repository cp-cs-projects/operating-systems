from collections import deque, OrderedDict

class memory:
    def __init__(self, size, store):
        self.size = size
        self.memory = [None] * size
        self.page_table = {}
        # page table entries will be {k, v} 
        # where k is the page number and v is [frame number, reference bit, valid bit]
        self.tlb = OrderedDict
        self.insert_order = deque() # may need this for FIFO
        self.last_used = {}
        self.faults = 0
        self.hits = 0
        self.tlb_hits = 0
        self.tlb_misses = 0
        self.store = store


    def get_page(self, page_number, PRA):
        # check if page is in TLB
        frame_number = self.tlb_lookup(page_number)
        if frame_number is not None:
            self.tlb_hits += 1
            # we may need to add a valid bit to the TLB
            # update the reference bit
            self.page_table[page_number][2] = 1 # update the reference bit?????
            return frame_number
        else:
            self.tlb_misses += 1
        # if not, check if page is already in memory
        if page_number in self.page_table:
            # check if page is valid
            if self.page_table[page_number][1] == 1: # if the page is valid
                self.hits += 1
                self.page_table[page_number][2] = 1 # update the reference bit
                # update the TLB
                self.add_tlb(page_number, self.page_table[page_number][0])
                return self.page_table[page_number][0] # return the frame number
        else: # page fault
            # check if there is a free frame
            self.faults += 1
            for i in range(self.size):
                if self.memory[i] is None:
                    self.memory[i] = page_number
                    self.page_table[page_number] = i
                    return i
            # this will only hit when all frames are full
            # now we need to deal with PRA
            if PRA == "FIFO":
                return self.fifo(page_number)
            elif PRA == "LRU":
                return self.lru(page_number)
            elif PRA == "OPT":
                return self.opt(page_number)
            else:
                return self.replace(page_number)
            

    def replace(self, page_number):
        return 0
        # this is a placeholder for hardcoded 256 frames with no pra



    ### TLB specific functions

    def add_tlb(self, page_number, frame_number):
        if len(self.tlb) >= 16:
            self.tlb.popitem(last=False) # FIFO
        self.tlb[page_number] = frame_number

    def tlb_lookup(self, page_number):
        if page_number in self.tlb:
            frame_number = self.tlb[page_number]
            # do we move this frame back to the end or preserve the order?
            self.tlb[page_number] = frame_number
            return frame_number
        else:
            return None

    


        
        