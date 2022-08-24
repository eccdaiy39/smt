### Algorithms

Based on the RELIC toolkit we implement:

* Subgroup membership tetsings for $\mathbb{G}_1$, $\G_2$ and $\G_T$ on the BN-P446 and BW13-P310 curves.<br/>
 1. The Elliptic Net algorithm (with lazy reduction).
 2. The improved Elliptic Net algorithm (with lazy reduction) by Chen et al in 2015.
 3. Faster algorithm based on the second algorithm.

We implement the optimal ate pairing on the BLS12-P381 curve and the KSS18-P676 curve. The preset file is in the preset folder, named gmp-pbc-bls381.sh and gmp-pbc-kss676.sh, respectively.

Miller's algorithm is implemented by the authors of this library (Deigo et al), we just run the existed function for comparison.

### Requirements

The build process requires the CMake cross-platform build system. The GMP library is also needed in our benchmarks.

### Build instructions

Instructions for building the library can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).

Here we give a direct way to verify our code.

1. Create a target directory : mkdir build
2. Locate the <preset> file in the preset folder and run the following:
cd build
../preset/<preset>.sh ../
make
3. Enter the bin folder and run the corresponding file.

List of our benchmark for implementation of the Ellpitic Net algorithm:

* elgmain_BLS12
* elgmain_KSS18

Notice that each preset file attached to only one benchmark here.
For example, we want to run the first benchmark, we should follow the three steps and choose the preset file gmp-pbc-bls381.sh.

### Source code

The source code of our algorithms distributed in different folders. Here we give a brief description.

* Pairings: relic-master/src/pp  en_**.c
* Main function of benchmark: relic-master/bench/  elgmain_**.c
* Some other functions: relic-master/src/fpx  tool.c

Notice that the file whose filename contains "tw" represents the computation is on the twisted curves.

