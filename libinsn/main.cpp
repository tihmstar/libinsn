//
//  main.cpp
//  libinsn
//
//  Created by tihmstar on 17.03.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <iostream>
#include "insn.hpp"

using namespace tihmstar::libinsn;

int main(int argc, const char * argv[]) {

    uint64_t opcode = 0xa9008801; //stp        x1, x2, [x0, #0x8]
    
    insn test(opcode,0);
    
    
    auto a = test.type();
    auto s =test.subtype();
    auto c = test.classtype();
    auto i = test.imm();
    
    insn t2 = insn::new_general_stp_offset(0, 8, 1, 2, 0);
    uint32_t opcode2 = t2.opcode();
    
    printf("");
    return 0;
}
