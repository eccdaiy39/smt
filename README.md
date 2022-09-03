### Algorithms

Based on the famous [RELIC cryptographic library](https://github.com/relic-toolkit/relic) we implement:

Subgroup membership tetsings for $\mathbb{G}_1$, $\mathbb{G}_2$ and $\mathbb{G}_T$ on the BN-P446 and BW13-P310 curves.
The preset file is in the preset folder, named x64-pbc-bn446.sh and gmp-ecc-bw310.sh, respectively.<br/>

### Requirements

The build process requires the [CMake](https://cmake.org/) cross-platform build system. The [GMP](https://gmplib.org/) library is also needed in our benchmarks.

### Build instructions

Instructions for building the library can be found in the [Wiki](https://github.com/relic-toolkit/relic/wiki/Building).


### Source code
  
The main source code of our algorithms are presented in [relic_pc_until.c](https://github.com/eccdaiy39/smt/blob/master/smt-relic/src/pc/relic_pc_util.c), which includes the following functions:<br/>

* g2_is_valid_bn(const g2_t a): $\mathbb{G}_2$ membership testing on the BN-P446 curve.<br/>
* gt_is_valid_bn(gt_t a): $\mathbb{G}_T$ membership testing on the BN-P446 curve.<br/>
* g1_is_valid_bw13(ep_t a) $\mathbb{G}_1$ membership testing on the BW13-P310 curve. <br/>
* g2_is_valid_bw13(ep_t a) $\mathbb{G}_2$ membership testing on the BW13-P310 curve. <br/>
* gt_is_valid_bw13(ep_t a) $\mathbb{G}_T$ membership testing on the BW13-P310 curve. <br/>

 Note the the previous fastest memberhship testings algotithms on the BN-P446 curve are presented in functions g2_is_valid(const g2_t a) and gt_is_valid(const gt_t a), respectively.

 ### Benckmarks
 The function for benckmarking are presented in [bench_pc.c](https://github.com/eccdaiy39/smt/blob/master/smt-relic/bench/bench_pc.c) for the BN-P446 curve and 
 [bench_pc_bw13.c](https://github.com/eccdaiy39/smt/blob/master/smt-relic/bench/bench_pc_bw13.c) for the BW13-P310 curve.
 Here we give a direct way to obtain concrete datas.
  - #### BN-P446

  1. mkdir build && cd build 
  2. ../preset/x64-pbc-bn446.sh ../
  3. make
  4. cd bin && ./bench_pc

![image](https://github.com/eccdaiy39/smt/blob/master/image/G2-BN.png)
![image](https://github.com/eccdaiy39/smt/blob/master/image/GT-BN.png)

 - #### BW13-P310

  1. mkdir build && cd build 
  2. ../preset/gmp-ecc-bw310.sh ../
  3. make
  4. cd bin && ./bench_pc_bw13
  
![image](https://github.com/eccdaiy39/smt/blob/master/image/BW13.png)

### Contact
 email:daiy39@mail2.sysu.edu.cn<br/>
 please contact me via email for any questions.

