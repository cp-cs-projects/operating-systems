#!/usr/local/bin/python3
import TLB
import main_memory
import page_table
import backing_store
import sys


# ./memSim.py <reference-sequence-file.txt> <FRAMES> <PRA>
# Q: default algs, only 2 args needed?
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
    
    bs = backing_store.BackingStore()
    mem = main_memory.memory(frames, bs.store)
    # 1. read the input file, extract addr, page_num, offset
    reference_sequence = []
    for line in reference_file:
        reference_sequence.append(int(line.strip()))
    reference_file.close()

    # 2. look up the page in the TLB

    # 3. on miss, check page table

    # 4. on page miss, page fault. read page from backing store, use pra to choose frame if no free exists, update page table & TLB
    
    # 5. compute physical addr and read byte from main memory.
    # TODO: need to intialize and populate the page table
    # TODO: need to intialize and populate the backing store

        


    return 0

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)