#!/usr/local/bin/python3
from main_memory import memory
from backing_store import BackingStore
import sys


# ./memSim.py <reference-sequence-file.txt> <FRAMES> <PRA>
def main(argc, argv):
    # Check if the number of arguments is correct
    if argc != 4:
        print("Usage: memSim.py <reference-sequence-file.txt> <FRAMES> <PRA>")
        return 1
    frames = argv[2]
    pra = argv[3]
    if(frames.isdigit() == False):
        print("FRAMES must be an integer between 1 and 256 inclusive")
        return 1
    frames = int(frames)
    if (frames < 1 or frames > 256):
        print("FRAMES must be an integer between 1 and 256 inclusive")
        return 1
    if( pra != "LRU" and pra != "FIFO" and pra != "OPT"):
        print("Page replacement algorithm must be FIFO, LRU, or OPT")
        return 1
    try:
        reference_file = open(argv[1], "r")
    except FileNotFoundError:
        print("Reference sequence file not found")
        return 1
    
    bs = BackingStore()
    mem = memory(frames, bs, pra)

    # 1. read the input file, extract addr, page_num, offset
    num_addresses = 0
    for line in reference_file:
        address = int(line.strip())
        page_num = address >> 8
        offset = address & 0xFF

        # get signed int byte from physicaly memory
        frame_number = mem.get_page(page_num)
        byte = mem.memory[frame_number][offset]
        signed_byte = byte - 256 if byte > 127 else byte
        
        hex_data = bs.byte_array_to_hex_ascii(mem.memory[frame_number])
        print(f"{address}, {signed_byte}, {frame_number}, {hex_data}")
        num_addresses += 1
        #reference_sequence.append([address, page_num, offset])
        # print(f"Address: {address}, Page Number: {page_num}, Offset: {offset}")
    reference_file.close()

    # for address, page_num, _ in reference_sequence:
    #     frame_number = mem.get_page(page_num)
    #     print(f'{address}, {frame_number}, {bs.print_data(page_num)}\n')

    print(f'Number of Translated Addresses = {num_addresses}')
    print(f"Page Faults = {mem.faults}")
    print(f"Page Fault Rate = {mem.faults/num_addresses:.3f}")
    print(f"TLB Hits = {mem.tlb_hits}")
    print(f"TLB Misses = {mem.tlb_misses}")
    print(f"TLB Hit Rate = {mem.tlb_hits/(mem.tlb_hits + mem.tlb_misses):.3f}")
    return 0

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)