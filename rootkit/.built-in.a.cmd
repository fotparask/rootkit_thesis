savedcmd_samples/rootkit/built-in.a := rm -f samples/rootkit/built-in.a;  printf "samples/rootkit/%s " rootkit.o | xargs llvm-ar cDPrST samples/rootkit/built-in.a
