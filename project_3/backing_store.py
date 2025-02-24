class BackingStore:
    def __init__(self, filename="BACKING_STORE.bin"):
        self.filename = filename
        self.store = self.fill_store()
    
    def read_page(self, page_number): 
        # read 256 byte page from the backing store
        start = page_number * 256 # convert back to actual index in array
        end = start + 256
        return self.store[start:end]

    def fill_store(self):
        chunk_size = 256
        i = 0
        store = bytearray()

        with open(self.filename, 'rb') as file:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                store.extend(chunk)
                i += 1
                
            return store   
        
    def print_data(self, page_number):
        page = self.read_page(page_number)
        hex_data = self.byte_array_to_hex_ascii(page)
        return hex_data


    def byte_array_to_hex_ascii(self, byte_array): # got this from google
        return ''.join([f'{byte:02x}' for byte in byte_array])  