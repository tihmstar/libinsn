//
//  main.cpp
//  libinsn
//
//  Created by tihmstar on 17.03.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <iostream>
#include "insn.hpp"
#include "vmem.hpp"

using namespace tihmstar::libinsn;

int main(int argc, const char * argv[]) {    
    uint64_t opcode = 0xD65F0BFF;
    arm64::insn test(opcode,0xfffffff00819d54c);
    
//    arm32::arm test(0xE92D40F0,0x803b65c0);
//    arm32::thumb test(0x0ebf75f0,0x00006e9b);
//    arm32::thumb test(0x601368C2,0);
//    arm32::arm test(0xA000008,0);

//
//    auto otest = arm32::thumb::new_T2_immediate_b(0x220002aa, 0x22000110);
//    printf("0x%08x\n",otest.opcode());

    auto a = test.type();
//    auto s = test.subtype();
    auto pt = test.pactype();
//    auto i = test.imm();
//    printf("dst=0x%08x\n",i);

//    auto rn = test.rn();
//    auto rd = test.rd();
//    auto rm = test.rm();
//    auto rt = test.rt();
//    auto t = test.supertype();
//    auto c = test.classtype();
//    auto regs = test.reglist();
//    auto special = test.special();
//
    
//    auto list = test.reglist();
    
    auto t2 = arm64::insn::new_immediate_ands(0xfffffff00823a26c, 0xff0000, 8, 31, true);
    uint32_t opcode2 = t2.opcode();
    
    printf("");
    return 0;
}
