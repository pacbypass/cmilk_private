'''
    // The amount of files in the directory
    // num_entries appears only once
    num_entries: u64,

    // this gets repeat `num_entries` times
    struct ftar
    {
        filelen: u64,
        filedata: Vec<u8>,
    }
'''
from pathlib import Path
import os
import sys

if len(sys.argv) > 2:
    fname = sys.argv[2]
    if os.path.exists(fname):
        os.remove(fname)

    # Output filename
    f = open(fname, "wb");

    # Recursively get all filenames and dirnames in the directory
    files_and_dirs = Path(sys.argv[1]).rglob("*")
    
    # I am sure that you can do this in a cleaner way
    # with some python magic that I don't know

    # filter out the directories, and get access to file 
    # length, which will be used as num_entries
    for name in files_and_dirs:
        if os.path.isfile(name):
            filenames.append(name)
    
    # Write the num_entries
    f.write(len(filenames).to_bytes(8, byteorder='little'))
    for path in filenames:
        handle = open(path, "rb")
        data = handle.read()
        f.write(len(data).to_bytes(8, byteorder='little'))
        f.write(data)
        handle.close()
        print("{}:  {} {}".format(path, len(filenames), len(data)))

    f.close()
else:
    print("usage: \n\t python3 {} input_directory output_filename\n\t".format(sys.argv[0]))