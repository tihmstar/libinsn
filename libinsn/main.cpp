//
//  main.cpp
//  libinsn
//
//  Created by tihmstar on 17.03.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <iostream>
#include "insn.hpp"
#include "insn32_thumb.hpp"

using namespace tihmstar::libinsn;

int main(int argc, const char * argv[]) {

    insn32_thumb mcpu(0x41424344, 0x41414141);
    
    mcpu.type();
    
    
    printf("");
    return 0;
}
