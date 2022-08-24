### Algorithms

Based on the RELIC toolkit we implement:

Subgroup membership tetsings for $\mathbb{G}_1$, $\mathbb{G}_2$ and $\mathbb{G}_T$ on the BN-P446 and BW13-P310 curves.
The preset file is in the preset folder, named gmp-pbc-bls381.sh and gmp-pbc-kss676.sh, respectively.<br/>

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
  
The main source code of our algorithms are presented in [relic_pc_until.c file](https://github.com/eccdaiy39/smt/blob/master/smt-relic/src/pc/relic_pc_util.c), which includes the following functions:<br\>

* int g2_is_valid_bn(const g2_t a): $\mathbb{G}_2$ membership testing on the BN family.<br\>
* int gt_is_valid_bn(gt_t a): $\mathbb{G}_T$ membership testing on the BN family.<br\>
* int g1_is_valid_bw13(ep_t a) $\mathbb{G}_1$ membership testing on the BW13-P310 curve. <br\>
* int g2_is_valid_bw13(ep_t a) $\mathbb{G}_2$ membership testing on the BW13-P310 curve. <br\>
* int gt_is_valid_bw13(ep_t a) $\mathbb{G}_t$ membership testing on the BW13-P310 curve. <br\>
* Some other functions: relic-master/src/fpx  tool.c
Notice that the file whose filename contains "tw" represents the computation is on the twisted curves.
  ### Benckmarks


