class BackingStore:
    def __init__(self, filename="BACKING_STORE.bin"):
        self.filename = filename
        with open(filename, "rb") as f:
            self.store = f.read()

    def read_page(self, page_number): 
        # read 256 byte page from the backing store
        start = page_number * 256
        end = start + 256
        return self.store[start:end]
