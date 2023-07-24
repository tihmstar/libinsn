//
//  arm32_arm_encode.cpp
//  libinsn
//
//  Created by erd on 06.07.23.
//  Copyright © 2023 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>
#include "../include/libinsn/INSNexception.hpp"
#include "../include/libinsn/arm32/arm32_arm.hpp"

#ifdef DEBUG
#   include <stdint.h>
__attribute__((unused)) static constexpr uint32_t BIT_RANGE(uint32_t v, int begin, int end) { return ((v)>>(begin)) % (1UL << ((end)-(begin)+1)); }
__attribute__((unused)) static constexpr uint32_t BIT_AT(uint32_t v, int pos){ return (v >> pos) & 1; }
__attribute__((unused)) static constexpr uint32_t SET_BITS(uint32_t v, int begin) { return (((uint32_t)v)<<(begin));}
#else
#   define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1UL << ((end)-(begin)+1)) )
#   define BIT_AT(v,pos) ( (v >> pos) & 1 )
#   define SET_BITS(v, begin) ((((uint32_t)v)<<(begin)))
#endif

using namespace tihmstar::libinsn::arm32;

#pragma mark general

arm arm::new_A1_general_bx(loc_t pc, uint8_t rm){
    return {
        static_cast<uint32_t>(SET_BITS(0b1110, 28) |
                              SET_BITS(0b10010, 20) |
                              SET_BITS(0xfff, 8) |
                              SET_BITS(0b0001, 4) |
                              SET_BITS(rm & 0b1111, 0))
        ,pc
    };
}

#pragma mark immediate

arm arm::new_A1_immediate_mov(loc_t pc, int16_t imm, uint8_t rd){
    return {
        static_cast<uint32_t>(SET_BITS(0b1110, 28) |
                              SET_BITS(0b0011101, 21) |
                              SET_BITS(rd & 0b111, 12) |
                              SET_BITS(imm & 0xfff, 0))
        ,pc
    };
}

#pragma mark literal
