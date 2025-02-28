from collections import deque, OrderedDict

# Constants
TLB_SIZE = 16

class memory:
    def __init__(self, size, store, PRA):
        self.size = size
        self.memory = [None] * size
        self.page_table = {} # {page_number: [frame_number, valid_bit]}
        self.tlb = OrderedDict()
        self.insert_order = deque()
        self.page_refs = {}
        self.faults = 0
        self.hits = 0
        self.tlb_hits = 0
        self.tlb_misses = 0
        self.store = store
        self.pra = PRA


    def get_page(self, page_number):
        if self.pra == "OPT":
            self.page_refs[page_number].pop(0)
            if len(self.page_refs[page_number]) == 0:
                self.page_refs[page_number].append(float('inf')) # if no more references, set to infinity
        # check if page is in TLB
        frame_number = self.tlb_lookup(page_number)
        if frame_number is not None:
            self.tlb_hits += 1
            if (self.pra == "LRU"):
                self.insert_order.remove(page_number)
                self.insert_order.append(page_number)
            return frame_number 
        else:
            self.tlb_misses += 1

        # if not, check if page is already in memory and is valid
        if page_number in self.page_table and self.page_table[page_number][1] == 1:     
                self.hits += 1
                frame_number = self.page_table[page_number][0]
                # update the TLB
                self.add_tlb(page_number, frame_number)
                if (self.pra == "LRU"):
                    self.insert_order.remove(page_number)
                    self.insert_order.append(page_number)

                return frame_number
        else: # page fault
            # check if there is a free frame
            self.faults += 1
            frame_number = self.page_fault(page_number)
            return frame_number
            
    
    def page_fault(self, page_number):
        # finding free frame
        for frame_number in range(self.size):
            if self.memory[frame_number] is None:
                return self.load_from_bs(page_number, frame_number)
            # this will only hit when all frames are full
            # now we need to deal with PRA
        if self.pra == "FIFO" or self.pra == "LRU":
            return self.evict_victim(page_number)
        else:
            return self.evict_victim_opt(page_number)
    
    def load_from_bs(self, page_number, frame_number):
        data = self.store.read_page(page_number)
        self.memory[frame_number] = data
        self.page_table[page_number] = [frame_number, 1]
        self.insert_order.append(page_number)
        self.add_tlb(page_number, frame_number)
        return frame_number
    
    def evict_victim(self, page_number):
        # remove the oldest page
        oldest = self.insert_order.popleft()
        frame_number = self.page_table[oldest][0]
        
        # update the page table to invalidate evicted page, remove from tlb
        self.page_table[oldest][1] = 0

        if oldest in self.tlb:
            del self.tlb[oldest]
        
        # add the new page and update tlb
        frame_number = self.load_from_bs(page_number, frame_number)
        return frame_number
    
    def evict_victim_opt(self, page_number):
        # find page accessed furthest in the future
        future_refs = {}
        for page in self.page_table:
            if self.page_table[page][1] == 1: # in frame
                future_refs[page] = self.page_refs[page][0]

        furthest = max(future_refs, key=lambda k: future_refs[k])
        frame_number = self.page_table[furthest][0]
        
        # update the page table
        self.page_table[furthest][1] = 0

        if furthest in self.tlb:
            del self.tlb[furthest]
        
        # add the new page and update tlb
        frame_number = self.load_from_bs(page_number, frame_number)
        return frame_number

    ### TLB specific functions

    def add_tlb(self, page_number, frame_number):
        if len(self.tlb) >= TLB_SIZE:
            self.tlb.popitem(last=False) # FIFO
        self.tlb[page_number] = frame_number

    def tlb_lookup(self, page_number):
        if page_number in self.tlb:
            frame_number = self.tlb[page_number]
            return frame_number
        else:
            return None

    


        
        