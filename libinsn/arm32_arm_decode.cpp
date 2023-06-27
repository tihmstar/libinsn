//
//  arm.cpp
//  libinsn
//
//  Created by tihmstar on 30.06.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#include "../include/libinsn/arm32/arm32_arm.hpp"

#ifdef DEBUG
#   include <stdint.h>
static constexpr uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); }
static constexpr uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) % 2; }
static constexpr uint64_t SET_BITS(uint64_t v, int begin) { return ((v)<<(begin));}
#else
#   define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1 << ((end)-(begin)+1)) )
#   define BIT_AT(v,pos) ( (v >> pos) % 2 )
#   define SET_BITS(v, begin) (((v)<<(begin)))
#endif

using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

arm::arm(uint32_t opcode, uint32_t pc)
: _opcode(opcode), _pc(pc), _type(unknown), _subtype(st_general), _supertype(sut_general)
{
    //
}

arm::~arm(){
    //
}

struct regtypes{
    enum arm32::type type;
    enum arm32::subtype subtype;
    enum arm32::supertype supertype;
};

typedef regtypes (*insn_type_test_func)(uint32_t);

struct decoder_val{
    bool isInsn;
    union {
        regtypes types;
        const insn_type_test_func next_stage_decoder;
    };
};

#pragma mark second stage decoders arm32

constexpr regtypes data_processing_and_misc_instructions_decoder_0(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn[(1<<9)]; //9bit
        constexpr decoder_stage2() : _stage2_insn{}
        {
            //Data-processing (register) on page A5-197
            for (int i=0; i<0b10000; i++) _stage2_insn[0b000000000 | SET_BITS(i,1)] = {arm32::and_,arm32::st_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b000100000 | SET_BITS(i,1)] = {arm32::eor,arm32::st_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b001000000 | SET_BITS(i,1)] = {arm32::sub,arm32::st_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b001100000 | SET_BITS(i,1)] = {arm32::rsb,arm32::st_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b010000000 | SET_BITS(i,1)] = {arm32::add,arm32::st_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b010100000 | SET_BITS(i,1)] = {arm32::adc,arm32::st_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b011000000 | SET_BITS(i,1)] = {arm32::sbc,arm32::st_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b011100000 | SET_BITS(i,1)] = {arm32::rsc,arm32::st_register};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b100010000 | SET_BITS(i,1)] = {arm32::tst,arm32::st_register};
            for (int i=0; i<0b1000; i++) _stage2_insn[0b100110000 | SET_BITS(i,1)] = {arm32::teq,arm32::st_register};
            for (int i=0; i<0b1000; i++) _stage2_insn[0b101010000 | SET_BITS(i,1)] = {arm32::cmp,arm32::st_register};
            for (int i=0; i<0b1000; i++) _stage2_insn[0b101110000 | SET_BITS(i,1)] = {arm32::cmn,arm32::st_register};

            for (int i=0; i<0b10000; i++) _stage2_insn[0b110000000 | SET_BITS(i,1)] = {arm32::orr,arm32::st_register};

            for (int i=0; i<0b100; i++) _stage2_insn[0b110100000 | SET_BITS(i,3)] = {arm32::mov,arm32::st_register};
            for (int i=0; i<0b100; i++) _stage2_insn[0b110100010 | SET_BITS(i,3)] = {arm32::lsr,arm32::st_immediate};
            for (int i=0; i<0b100; i++) _stage2_insn[0b110100100 | SET_BITS(i,3)] = {arm32::asr,arm32::st_immediate};
            for (int i=0; i<0b100; i++) _stage2_insn[0b110100110 | SET_BITS(i,3)] = {arm32::rrx};
            
            for (int i=0; i<0b10000; i++) _stage2_insn[0b111000000 | SET_BITS(i,1)] = {arm32::bic,arm32::st_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b111100000 | SET_BITS(i,1)] = {arm32::mvn,arm32::st_register};
            
            //Data-processing (register-shifted register) on page A5-198
            for (int i=0; i<0b10000; i++) _stage2_insn[0b000000001 | SET_BITS(i,1)] = {arm32::and_,arm32::st_register_shifted_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b000100001 | SET_BITS(i,1)] = {arm32::eor,arm32::st_register_shifted_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b001000001 | SET_BITS(i,1)] = {arm32::sub,arm32::st_register_shifted_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b001100001 | SET_BITS(i,1)] = {arm32::rsb,arm32::st_register_shifted_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b010000001 | SET_BITS(i,1)] = {arm32::add,arm32::st_register_shifted_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b010100001 | SET_BITS(i,1)] = {arm32::adc,arm32::st_register_shifted_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b011000001 | SET_BITS(i,1)] = {arm32::sbc,arm32::st_register_shifted_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b011100001 | SET_BITS(i,1)] = {arm32::rsc,arm32::st_register_shifted_register};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b100010001 | SET_BITS(i,1)] = {arm32::tst,arm32::st_register_shifted_register};
            for (int i=0; i<0b1000; i++) _stage2_insn[0b100110001 | SET_BITS(i,1)] = {arm32::teq,arm32::st_register_shifted_register};
            for (int i=0; i<0b1000; i++) _stage2_insn[0b101010001 | SET_BITS(i,1)] = {arm32::cmp,arm32::st_register_shifted_register};
            for (int i=0; i<0b1000; i++) _stage2_insn[0b101110001 | SET_BITS(i,1)] = {arm32::cmn,arm32::st_register_shifted_register};

            for (int i=0; i<0b10000; i++) _stage2_insn[0b110000001 | SET_BITS(i,1)] = {arm32::orr,arm32::st_register_shifted_register};

            for (int i=0; i<0b10; i++) _stage2_insn[0b110100001 | SET_BITS(i,4)] = {arm32::lsl,arm32::st_register};
            for (int i=0; i<0b10; i++) _stage2_insn[0b110100011 | SET_BITS(i,4)] = {arm32::lsr,arm32::st_register};
            for (int i=0; i<0b10; i++) _stage2_insn[0b110100101 | SET_BITS(i,4)] = {arm32::asr,arm32::st_register};
            for (int i=0; i<0b10; i++) _stage2_insn[0b110100111 | SET_BITS(i,4)] = {arm32::ror,arm32::st_register};

            for (int i=0; i<0b10000; i++) _stage2_insn[0b111000001 | SET_BITS(i,1)] = {arm32::bic,arm32::st_register_shifted_register};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b111100001 | SET_BITS(i,1)] = {arm32::mvn,arm32::st_register_shifted_register};
            
            //Miscellaneous instructions on page A5-207
            _stage2_insn[0b100000000] = {arm32::mrs};
            _stage2_insn[0b101000000] = {arm32::mrs};

            _stage2_insn[0b100100000] = {arm32::msr, arm32::st_register};
            _stage2_insn[0b101100000] = {arm32::msr, arm32::st_register};
            
            _stage2_insn[0b100100001] = {arm32::bx};
            _stage2_insn[0b101100001] = {arm32::clz};
            _stage2_insn[0b100100010] = {arm32::bxj};
            _stage2_insn[0b100100011] = {arm32::blx};

            {
                //action Saturating addition and subtraction on page A5-202
                _stage2_insn[0b100000101] = {arm32::qadd};
                _stage2_insn[0b100100101] = {arm32::qsub};
                _stage2_insn[0b101000101] = {arm32::qdadd};
                _stage2_insn[0b101100101] = {arm32::qdsub};
            }

            _stage2_insn[0b101100110] = {arm32::eret};

            _stage2_insn[0b100100111] = {arm32::bkpt};
            _stage2_insn[0b101000111] = {arm32::hvc};
            _stage2_insn[0b101100111] = {arm32::smc};

            
            //Halfword multiply and multiply accumulate on page A5-203
#warning TODO: implement this ._. maybe
            
            //Multiply and multiply accumulate on page A5-202
            for (int i=0; i<0b10; i++) _stage2_insn[0b000001001 | SET_BITS(i,4)] = {arm32::mul};
            for (int i=0; i<0b10; i++) _stage2_insn[0b000101001 | SET_BITS(i,4)] = {arm32::mla};
            _stage2_insn[0b001001001] = {arm32::umaal};
            _stage2_insn[0b001101001] = {arm32::mls};
            for (int i=0; i<0b10; i++) _stage2_insn[0b010001001 | SET_BITS(i,4)] = {arm32::umull};
            for (int i=0; i<0b10; i++) _stage2_insn[0b010101001 | SET_BITS(i,4)] = {arm32::umlal};
            for (int i=0; i<0b10; i++) _stage2_insn[0b011001001 | SET_BITS(i,4)] = {arm32::smull};
            for (int i=0; i<0b10; i++) _stage2_insn[0b011101001 | SET_BITS(i,4)] = {arm32::smlal};

            //Synchronization primitives on page A5-205
            _stage2_insn[0b100001101] = {arm32::swp};
            _stage2_insn[0b101001101] = {arm32::swpb};
            _stage2_insn[0b110001101] = {arm32::strex};
            _stage2_insn[0b110011101] = {arm32::ldrex};
            _stage2_insn[0b110101101] = {arm32::strexd};
            _stage2_insn[0b110111101] = {arm32::ldrexd};
            _stage2_insn[0b111001101] = {arm32::strexb};
            _stage2_insn[0b111011101] = {arm32::ldrexb};
            _stage2_insn[0b111101101] = {arm32::strexh};
            _stage2_insn[0b111111101] = {arm32::ldrexh};

            //Extra load/store instructions on page A5-203
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b000001011 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::strh, arm32::st_register, arm32::sut_memory};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b000011011 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::ldrh, arm32::st_register, arm32::sut_memory};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b001001011 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::strh, arm32::st_immediate, arm32::sut_memory};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b001011011 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::ldrh, arm32::st_immediate, arm32::sut_memory};

            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b000001101 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::ldrd, arm32::st_register, arm32::sut_memory};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b000011101 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::ldrsb, arm32::st_register, arm32::sut_memory};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b001001101 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::ldrd, arm32::st_immediate, arm32::sut_memory};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b001011101 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::ldrsb, arm32::st_immediate, arm32::sut_memory};

            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b000001111 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::strd, arm32::st_register, arm32::sut_memory};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b000011111 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::ldrsh, arm32::st_register, arm32::sut_memory};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b001001111 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::strd, arm32::st_immediate, arm32::sut_memory};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b10; j++) _stage2_insn[0b001011111 | SET_BITS(i,7) | SET_BITS(j,5)] = {arm32::ldrsh, arm32::st_immediate, arm32::sut_memory};

            //Extra load/store instructions, unprivileged on page A5-204
            for (int i=0; i<0b100; i++) _stage2_insn[0b000101011 | SET_BITS(i,6)] = {arm32::strht, arm32::st_immediate, arm32::sut_memory};
            for (int i=0; i<0b100; i++) _stage2_insn[0b000111011 | SET_BITS(i,6)] = {arm32::ldrht, arm32::st_immediate, arm32::sut_memory};
            for (int i=0; i<0b100; i++) _stage2_insn[0b000111101 | SET_BITS(i,6)] = {arm32::ldrsbt, arm32::st_immediate, arm32::sut_memory};
            for (int i=0; i<0b100; i++) _stage2_insn[0b000111111 | SET_BITS(i,6)] = {arm32::ldrsht, arm32::st_immediate, arm32::sut_memory};
        }
        constexpr regtypes operator[](uint16_t i) const{
            return _stage2_insn[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
        
    auto predec = decode_table_stage2[(BIT_RANGE(i,20,24) << 4) | BIT_RANGE(i,4,7)];
    
    switch (predec.type) {
        case arm32::ldrsh:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::ldrsh, arm32::st_literal};
            }
            break;

        case arm32::ldrsb:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::ldrsb, arm32::st_literal};
            }
            break;

        case arm32::ldrd:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::ldrd, arm32::st_literal};
            }
            break;

        case arm32::ldrh:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::ldrh, arm32::st_literal};
            }
            break;

        case arm32::rrx:
            if (BIT_RANGE(i, 7, 11)) {
                return {arm32::ror, arm32::st_immediate};
            }
            break;

        case arm32::mov:
            if (BIT_RANGE(i, 7, 11)) {
                return {arm32::lsl, arm32::st_immediate};
            }
            break;
            
        default:
            break;
    }
    
    return predec;
}

constexpr regtypes data_processing_and_misc_instructions_decoder_1(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn[(1<<5)]; //5bit
        constexpr decoder_stage2() : _stage2_insn{}
        {
            //Data-processing (immediate) on page A5-199
            for (int i=0; i<0b10; i++) _stage2_insn[0b00000 | SET_BITS(i,0)] = {arm32::and_,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b00010 | SET_BITS(i,0)] = {arm32::eor,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b00100 | SET_BITS(i,0)] = {arm32::sub,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b00110 | SET_BITS(i,0)] = {arm32::rsb,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b01000 | SET_BITS(i,0)] = {arm32::add,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b01010 | SET_BITS(i,0)] = {arm32::adc,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b01100 | SET_BITS(i,0)] = {arm32::sbc,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b01110 | SET_BITS(i,0)] = {arm32::rsc,arm32::st_immediate};

            _stage2_insn[0b10001] = {arm32::tst,arm32::st_immediate};
            _stage2_insn[0b10011] = {arm32::teq,arm32::st_immediate};
            _stage2_insn[0b10101] = {arm32::cmp,arm32::st_immediate};
            _stage2_insn[0b10111] = {arm32::cmn,arm32::st_immediate};

            for (int i=0; i<0b10; i++) _stage2_insn[0b11000 | SET_BITS(i,0)] = {arm32::orr,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b11010 | SET_BITS(i,0)] = {arm32::mov,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b11100 | SET_BITS(i,0)] = {arm32::bic,arm32::st_immediate};
            for (int i=0; i<0b10; i++) _stage2_insn[0b11110 | SET_BITS(i,0)] = {arm32::mvn,arm32::st_immediate};

            //others
            _stage2_insn[0b10000] = {arm32::mov,arm32::st_immediate};
            _stage2_insn[0b10100] = {arm32::movt,arm32::st_immediate};

            //MSR (immediate), and hints on page A5-206
            _stage2_insn[0b10010] = {arm32::msr,arm32::st_immediate};
            _stage2_insn[0b10110] = {arm32::nop};
        }
        constexpr regtypes operator[](uint16_t i) const{
            return _stage2_insn[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
        
    auto predec = decode_table_stage2[BIT_RANGE(i,20,24)];
    
    switch (predec.type) {
        case arm32::nop:
            if (BIT_RANGE(i, 16, 19) == 0) {
                switch (BIT_RANGE(i, 0, 7)) {
                    case 0b00000000:
                        return {arm32::nop};
                    case 0b00000001:
                        return {arm32::yield};
                    case 0b00000010:
                        return {arm32::wfe};
                    case 0b00000011:
                        return {arm32::wfi};
                    case 0b00000100:
                        return {arm32::sev};
                    default: //0b1111xxxx
                        return {arm32::dbg};
                }
            }else{
                return {arm32::msr, arm32::st_immediate};
            }
            break;
            
        case arm32::add:
        case arm32::sub:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::adr};
            }
            break;
            
        default:
            break;
    }
    
    return predec;
}
    
constexpr regtypes load_store_word_unsigned_byte_A0_decoder(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn[(1<<6)]; //6bit
        constexpr decoder_stage2() : _stage2_insn{}
        {
            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b000000 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::str,arm32::st_immediate,arm32::sut_memory};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b000001 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::str,arm32::st_immediate,arm32::sut_memory};
            //overwrites previous encoding!
            for (int i=0; i<0b10; i++) _stage2_insn[0b000100 | SET_BITS(i,4)] = {arm32::strt,arm32::st_general,arm32::sut_memory};
            for (int i=0; i<0b10; i++) _stage2_insn[0b000101 | SET_BITS(i,4)] = {arm32::strt,arm32::st_general,arm32::sut_memory};
            
            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b000010 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::ldr,arm32::st_immediate,arm32::sut_memory};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b000011 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::ldr,arm32::st_literal,arm32::sut_memory};
            //overwrites previous encoding!
            for (int i=0; i<0b10; i++) _stage2_insn[0b000110 | SET_BITS(i,4)] = {arm32::ldrt,arm32::st_general,arm32::sut_memory};
            for (int i=0; i<0b10; i++) _stage2_insn[0b000111 | SET_BITS(i,4)] = {arm32::ldrt,arm32::st_general,arm32::sut_memory};

            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b001000 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::strb,arm32::st_immediate,arm32::sut_memory};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b001001 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::strb,arm32::st_immediate,arm32::sut_memory};
            //overwrites previous encoding!
            for (int i=0; i<0b10; i++) _stage2_insn[0b001100 | SET_BITS(i,4)] = {arm32::strbt,arm32::st_general,arm32::sut_memory};
            for (int i=0; i<0b10; i++) _stage2_insn[0b001101 | SET_BITS(i,4)] = {arm32::strbt,arm32::st_general,arm32::sut_memory};

            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b001010 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::ldrb,arm32::st_immediate,arm32::sut_memory};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b001011 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::ldrb,arm32::st_literal,arm32::sut_memory};
            //overwrites previous encoding!
            for (int i=0; i<0b10; i++) _stage2_insn[0b001110 | SET_BITS(i,4)] = {arm32::ldrbt,arm32::st_general,arm32::sut_memory};
            for (int i=0; i<0b10; i++) _stage2_insn[0b001111 | SET_BITS(i,4)] = {arm32::ldrbt,arm32::st_general,arm32::sut_memory};
        }
        constexpr regtypes operator[](uint16_t i) const{
            return _stage2_insn[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
        
    return decode_table_stage2[(BIT_RANGE(i,20,24) << 1) | (BIT_RANGE(i, 16, 19) == 0b1111)];
}
    
constexpr regtypes load_store_word_unsigned_byte_A1_decoder(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn[(1<<5)]; //5bit
        constexpr decoder_stage2() : _stage2_insn{}
        {
            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b00000 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::str,arm32::st_register,arm32::sut_memory};
            //overwrites previous encoding!
            for (int i=0; i<0b10; i++) _stage2_insn[0b00010 | SET_BITS(i,4)] = {arm32::strt,arm32::st_general,arm32::sut_memory};
            
            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b00001 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::ldr,arm32::st_register,arm32::sut_memory};
            //overwrites previous encoding!
            for (int i=0; i<0b10; i++) _stage2_insn[0b00011 | SET_BITS(i,4)] = {arm32::ldrt,arm32::st_general,arm32::sut_memory};

            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b00100 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::strb,arm32::st_register,arm32::sut_memory};
            //overwrites previous encoding!
            for (int i=0; i<0b10; i++) _stage2_insn[0b00110 | SET_BITS(i,4)] = {arm32::strbt,arm32::st_general,arm32::sut_memory};

            for (int i=0; i<0b10; i++) for (int j=0; j<0b100; j++) _stage2_insn[0b00101 | SET_BITS(j,3) | SET_BITS(i,1)] = {arm32::ldrb,arm32::st_register,arm32::sut_memory};
            //overwrites previous encoding!
            for (int i=0; i<0b10; i++) _stage2_insn[0b00111 | SET_BITS(i,4)] = {arm32::ldrbt,arm32::st_general,arm32::sut_memory};
        }
        constexpr regtypes operator[](uint16_t i) const{
            return _stage2_insn[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
        
    return decode_table_stage2[BIT_RANGE(i,20,24)];
}
    
constexpr regtypes media_instructions_decoder(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn[(1<<8)]; //8bit
        constexpr decoder_stage2() : _stage2_insn{}
        {
            //Parallel addition and subtraction, signed on page A5-210
            {
                _stage2_insn[0b00001000] = {arm32::sadd16};
                _stage2_insn[0b00001001] = {arm32::sasx};
                _stage2_insn[0b00001010] = {arm32::ssax};
                _stage2_insn[0b00001011] = {arm32::ssub16};
                _stage2_insn[0b00001100] = {arm32::sadd8};
                _stage2_insn[0b00001111] = {arm32::ssub8};
                
                //Saturating instructions
                _stage2_insn[0b00010000] = {arm32::qadd16};
                _stage2_insn[0b00010001] = {arm32::qasx};
                _stage2_insn[0b00010010] = {arm32::qsax};
                _stage2_insn[0b00010011] = {arm32::qsub16};
                _stage2_insn[0b00010100] = {arm32::qadd8};
                _stage2_insn[0b00010111] = {arm32::qsub8};
                
                //Halving instructions
                _stage2_insn[0b00011000] = {arm32::shadd16};
                _stage2_insn[0b00011001] = {arm32::shasx};
                _stage2_insn[0b00011010] = {arm32::shsax};
                _stage2_insn[0b00011011] = {arm32::shsub16};
                _stage2_insn[0b00011100] = {arm32::shadd8};
                _stage2_insn[0b00011111] = {arm32::shsub8};
            }
            
            //Parallel addition and subtraction, unsigned on page A5-211
            {
                _stage2_insn[0b00101000] = {arm32::uadd16};
                _stage2_insn[0b00101001] = {arm32::uasx};
                _stage2_insn[0b00101010] = {arm32::usax};
                _stage2_insn[0b00101011] = {arm32::usub16};
                _stage2_insn[0b00101100] = {arm32::uadd8};
                _stage2_insn[0b00101111] = {arm32::usub8};
                
                //Saturating instructions
                _stage2_insn[0b00110000] = {arm32::uqadd16};
                _stage2_insn[0b00110001] = {arm32::uqasx};
                _stage2_insn[0b00110010] = {arm32::uqsax};
                _stage2_insn[0b00110011] = {arm32::uqsub16};
                _stage2_insn[0b00110100] = {arm32::uqadd8};
                _stage2_insn[0b00110111] = {arm32::uqsub8};
                
                //Halving instructions
                _stage2_insn[0b00111000] = {arm32::uhadd16};
                _stage2_insn[0b00111001] = {arm32::uhasx};
                _stage2_insn[0b00111010] = {arm32::uhsax};
                _stage2_insn[0b00111011] = {arm32::uhsub16};
                _stage2_insn[0b00111100] = {arm32::uhadd8};
                _stage2_insn[0b00111111] = {arm32::uhsub8};
            }
            
            //Packing, unpacking, saturation, and reversal on page A5-212
            {
                for (int i=0; i<0b100; i++) _stage2_insn[0b01000000 | SET_BITS(i,1)] = {arm32::pkh};
                _stage2_insn[0b01000011] = {arm32::sxtab16};
                _stage2_insn[0b01000101] = {arm32::sel};
                
                for (int i=0; i<0b1000; i++) _stage2_insn[0b01010000 | SET_BITS(i,1)] = {arm32::ssat};
                _stage2_insn[0b01010001] = {arm32::ssat16};
                _stage2_insn[0b01010011] = {arm32::sxtab};

                _stage2_insn[0b01011001] = {arm32::rev};
                _stage2_insn[0b01011011] = {arm32::sxtah};
                _stage2_insn[0b01011101] = {arm32::rev16};

                _stage2_insn[0b01100011] = {arm32::uxtab16};

                for (int i=0; i<0b1000; i++) _stage2_insn[0b01110000 | SET_BITS(i,1)] = {arm32::usat};

                _stage2_insn[0b01110001] = {arm32::usat16};
                _stage2_insn[0b01110011] = {arm32::uxtab};

                _stage2_insn[0b01111001] = {arm32::rbit};
                _stage2_insn[0b01111011] = {arm32::uxtah};
                _stage2_insn[0b01111101] = {arm32::revsh};
            }
            
            //Signed multiply, signed and unsigned divide on page A5-213
            {
                for (int i=0; i<0b10; i++) _stage2_insn[0b10000000 | SET_BITS(i,0)] = {arm32::smlad};
                for (int i=0; i<0b10; i++) _stage2_insn[0b10000010 | SET_BITS(i,0)] = {arm32::smlsd};

                _stage2_insn[0b10001000] = {arm32::sdiv};
                _stage2_insn[0b10001000] = {arm32::udiv};

                for (int i=0; i<0b10; i++) _stage2_insn[0b10100000 | SET_BITS(i,0)] = {arm32::smlald};
                for (int i=0; i<0b10; i++) _stage2_insn[0b10100010 | SET_BITS(i,0)] = {arm32::smlsld};

                for (int i=0; i<0b10; i++) _stage2_insn[0b10101000 | SET_BITS(i,0)] = {arm32::smmla};
                for (int i=0; i<0b10; i++) _stage2_insn[0b10101110 | SET_BITS(i,0)] = {arm32::smmls};
            }
            
            _stage2_insn[0b11000000] = {arm32::usada8};
            
            for (int i=0; i<0b100; i++) _stage2_insn[0b11010010 | SET_BITS(i,2)] = {arm32::sbfx};
            for (int i=0; i<0b100; i++) _stage2_insn[0b11100000 | SET_BITS(i,2)] = {arm32::bfi};
            for (int i=0; i<0b100; i++) _stage2_insn[0b11110010 | SET_BITS(i,2)] = {arm32::bfi};

            _stage2_insn[0b11111111] = {arm32::udf};
        }
        constexpr regtypes operator[](uint16_t i) const{
            return _stage2_insn[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
        
    auto predec = decode_table_stage2[(BIT_RANGE(i,20,24) << 3) | BIT_RANGE(i, 5, 7)];
    
    switch (predec.type) {
        case arm32::bfi:
            if (BIT_RANGE(i, 12, 15) == 0b1111) {
                return {arm32::bfc};
            }
            break;
        case arm32::usada8:
            if (BIT_RANGE(i, 12, 15) == 0b1111) {
                return {arm32::usad8};
            }
            break;
        case arm32::smmla:
            if (BIT_RANGE(i, 12, 15) == 0b1111) {
                return {arm32::smmul};
            }
            break;
        case arm32::smlsd:
            if (BIT_RANGE(i, 12, 15) == 0b1111) {
                return {arm32::smusd};
            }
            break;
        case arm32::smlad:
            if (BIT_RANGE(i, 12, 15) == 0b1111) {
                return {arm32::smuad};
            }
            break;
        case arm32::uxtah:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::uxth};
            }
            break;
        case arm32::uxtab:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::uxtb};
            }
            break;
        case arm32::uxtab16:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::uxtb16};
            }
            break;
        case arm32::sxtah:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::sxth};
            }
            break;
        case arm32::sxtab:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::sxtb};
            }
            break;
        case arm32::sxtab16:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::sxtb16};
            }
            break;
            
        default:
            break;
    }
    
    return predec;
}
    
constexpr regtypes b_bl_and_block_data_transfer_decoder(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn[(1<<6)]; //6bit
        constexpr decoder_stage2() : _stage2_insn{}
        {
            _stage2_insn[0b000000] = {arm32::stmed, arm32::st_general, arm32::sut_memory};
            _stage2_insn[0b000010] = {arm32::stmda, arm32::st_general, arm32::sut_memory};

            _stage2_insn[0b000001] = {arm32::ldmfa, arm32::st_general, arm32::sut_memory};
            _stage2_insn[0b000011] = {arm32::ldmda, arm32::st_general, arm32::sut_memory};

            _stage2_insn[0b001000] = {arm32::stmea, arm32::st_general, arm32::sut_memory};
            _stage2_insn[0b001010] = {arm32::stmia, arm32::st_general, arm32::sut_memory};

            _stage2_insn[0b001001] = {arm32::ldmfd, arm32::st_general, arm32::sut_memory};
            _stage2_insn[0b001011] = {arm32::ldmia, arm32::st_general, arm32::sut_memory};
            
            _stage2_insn[0b010000] = {arm32::stmfd, arm32::st_general, arm32::sut_memory};
            _stage2_insn[0b010010] = {arm32::stmdb, arm32::st_general, arm32::sut_memory};

            _stage2_insn[0b010001] = {arm32::ldmea, arm32::st_general, arm32::sut_memory};
            _stage2_insn[0b010011] = {arm32::ldmdb, arm32::st_general, arm32::sut_memory};

            _stage2_insn[0b011000] = {arm32::stmfa, arm32::st_general, arm32::sut_memory};
            _stage2_insn[0b011010] = {arm32::stmib, arm32::st_general, arm32::sut_memory};

            _stage2_insn[0b011001] = {arm32::ldmed, arm32::st_general, arm32::sut_memory};
            _stage2_insn[0b011011] = {arm32::ldmib, arm32::st_general, arm32::sut_memory};

            
            for (int i=0; i<0b100; i++) _stage2_insn[0b000100 | SET_BITS(i, 3)] = {arm32::stm, arm32::st_general, arm32::sut_memory};
            for (int i=0; i<0b100; i++) _stage2_insn[0b000110 | SET_BITS(i, 3)] = {arm32::stm, arm32::st_general, arm32::sut_memory};

            for (int i=0; i<0b100; i++) _stage2_insn[0b000101 | SET_BITS(i, 3)] = {arm32::ldm, arm32::st_general, arm32::sut_memory};
            for (int i=0; i<0b100; i++) _stage2_insn[0b000111 | SET_BITS(i, 3)] = {arm32::ldm, arm32::st_general, arm32::sut_memory};

            for (int i=0; i<0b10000; i++) _stage2_insn[0b100000 | SET_BITS(i, 0)] = {arm32::b, arm32::st_general, arm32::sut_branch_imm};
            for (int i=0; i<0b10000; i++) _stage2_insn[0b110000 | SET_BITS(i, 0)] = {arm32::bl, arm32::st_general, arm32::sut_branch_imm};
        }
        constexpr regtypes operator[](uint16_t i) const{
            return _stage2_insn[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
        
    auto predec = decode_table_stage2[BIT_RANGE(i,20,25)];
    
    switch (predec.type){
        case arm32::stmdb:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::push};
            }
            break;
        case arm32::ldmia:
            if (BIT_RANGE(i, 16, 19) == 0b1111) {
                return {arm32::pop};
            }
            break;

        default:
            break;
    }
    
    return predec;
}
    
constexpr regtypes coprocessor_instructions_and_supervisor_call_decoder(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn_not_101[(1<<6)]; //6bit
        regtypes _stage2_insn_is_101 [(1<<6)]; //6bit
        constexpr decoder_stage2() : _stage2_insn_not_101{},_stage2_insn_is_101{}
        {
            //_stage2_insn_not_101
            for (int i=0; i<0b10000; i++) _stage2_insn_not_101[0b000000 | SET_BITS(i, 1)] = {arm32::stc, arm32::st_general, arm32::sut_memory};
            for (int i=0; i<0b10000; i++) _stage2_insn_not_101[0b000000 | SET_BITS(i, 1)] = {arm32::ldc, arm32::st_immediate, arm32::sut_memory};

            _stage2_insn_not_101[0b000100] = {arm32::mcrr};
            _stage2_insn_not_101[0b000101] = {arm32::mrrc};

            for (int i=0; i<0b1000; i++) _stage2_insn_not_101[0b100000 | SET_BITS(i, 1)] = {arm32::mcr};
            for (int i=0; i<0b1000; i++) _stage2_insn_not_101[0b100001 | SET_BITS(i, 1)] = {arm32::mrc};

            //_stage2_insn_is_101
            
            //SIMD, Floating-point Extension register load/store instructions on page A7-274
            {
                for (int i=0; i<0b10; i++) _stage2_insn_not_101[0b000100 | SET_BITS(i, 0)] = {arm32::vmov};

                for (int i=0; i<0b100; i++) _stage2_insn_not_101[0b001000 | SET_BITS(i, 1)] = {arm32::vstm};
                for (int i=0; i<0b100; i++) _stage2_insn_not_101[0b010000 | SET_BITS(i, 2)] = {arm32::vstr};
                for (int i=0; i<0b10; i++) _stage2_insn_not_101[0b010010 | SET_BITS(i, 2)] = {arm32::vpush};

                for (int i=0; i<0b10; i++) _stage2_insn_not_101[0b001001 | SET_BITS(i, 2)] = {arm32::vldm};
                for (int i=0; i<0b10; i++) _stage2_insn_not_101[0b001011 | SET_BITS(i, 2)] = {arm32::vpop};
                for (int i=0; i<0b100; i++) _stage2_insn_not_101[0b010001 | SET_BITS(i, 2)] = {arm32::vldr};
                for (int i=0; i<0b10; i++) _stage2_insn_not_101[0b010011 | SET_BITS(i, 2)] = {arm32::vldm};
            }

            //overwrite 2 previous encodings!
            for (int i=0; i<0b10; i++) _stage2_insn_not_101[0b000100 | SET_BITS(i, 0)] = {arm32::vmov};

            //Floating-point data-processing instructions on page A7-272
            {
#warning TODO are we really gonna do floating point extension parsing?
            }

            //8, 16, and 32-bit transfer between ARM core and extension registers on page A7-278
            {
#warning TODO are we really gonna do floating point extension parsing?
            }
        }
        constexpr regtypes operator[](uint32_t i) const{
            if (BIT_RANGE(i, 9, 11) == 0b101) {
                auto predec = _stage2_insn_is_101[BIT_RANGE(i,20,25)];
                switch (predec.type) {
                    case arm32::vpop:
                        if (BIT_RANGE(i, 16, 19) != 0b1101) {
                            return {arm32::vldm};
                        }
                        break;
                    case arm32::vpush:
                        if (BIT_RANGE(i, 16, 19) != 0b1101) {
                            return {arm32::vstm};
                        }
                        break;

                    default:
                        break;
                }
                return predec;
            }else{
                auto predec = _stage2_insn_not_101[BIT_RANGE(i,20,25)];
                switch (predec.type) {
                    case arm32::ldc:
                        if (BIT_RANGE(i, 16, 19) == 0b1111) {
                            return {arm32::ldc, arm32::st_literal, arm32::sut_memory};
                        }
                        break;
                    case arm32::mcr:
                    case arm32::mrc:
                        if (BIT_AT(i, 4) == 0) {
                            return {arm32::cdp};
                        }
                        break;
                    default:
                        break;
                }
                return predec;
            }
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
    
    if (BIT_RANGE(i, 24, 25) == 0b11){
        return {arm32::svc};
    }
    
    return decode_table_stage2[i];
}

#pragma mark decoding unit arm32

struct decoder_stage1_arm32{
    decoder_val _stage1_cond_insn_cond[(1<<4)]; //4 bit
    decoder_val _stage1_cond_insn_uncond[(1<<8)]; //8 bit
    constexpr decoder_stage1_arm32() : _stage1_cond_insn_cond{},_stage1_cond_insn_uncond{}
    {
        //_stage1_cond_insn_cond
    
        //Data-processing and miscellaneous instructions on page A5-196.
        {
            _stage1_cond_insn_cond[0b0000] = {false, .next_stage_decoder = data_processing_and_misc_instructions_decoder_0};
            _stage1_cond_insn_cond[0b0001] = {false, .next_stage_decoder = data_processing_and_misc_instructions_decoder_1};
        }
        
        //Load/store word and unsigned byte on page A5-208
        {
            _stage1_cond_insn_cond[0b0100] = {false, .next_stage_decoder = load_store_word_unsigned_byte_A0_decoder};
            _stage1_cond_insn_cond[0b0101] = {false, .next_stage_decoder = load_store_word_unsigned_byte_A0_decoder};
            _stage1_cond_insn_cond[0b0110] = {false, .next_stage_decoder = load_store_word_unsigned_byte_A1_decoder};
            _stage1_cond_insn_cond[0b0111] = {false, .next_stage_decoder = media_instructions_decoder};
        }
        
        //Branch, branch with link, and block data transfer on page A5-214
        {
            for (int i=0; i<0b100; i++) _stage1_cond_insn_cond[0b1000 | SET_BITS(i, 0)] = {false, .next_stage_decoder = b_bl_and_block_data_transfer_decoder};
        }
        
        //Coprocessor instructions, and Supervisor Call on page A5-215.
        {
            for (int i=0; i<0b100; i++) _stage1_cond_insn_cond[0b1100 | SET_BITS(i, 0)] = {false, .next_stage_decoder = coprocessor_instructions_and_supervisor_call_decoder};
        }

        //_stage1_cond_insn_cond
        
        //Memory hints, Advanced SIMD instructions, and miscellaneous instructions on page A5-217
        {
            _stage1_cond_insn_uncond[0b00010000] = {true, {arm32::cps}};

            //See Advanced SIMD data-processing instructions on page A7-261
            {
#warning TODO do we even need Advanced SIMD?
            }
            
            //See Advanced SIMD element or structure load/store instructions on page A7-275
            {
#warning TODO do we even need Advanced SIMD?
            }

            for (int i=0; i<0b10; i++) _stage1_cond_insn_uncond[0b1000101 | SET_BITS(i, 3)] = {true, {arm32::pli}};
            for (int i=0; i<0b10; i++) _stage1_cond_insn_uncond[0b1010001 | SET_BITS(i, 3)] = {true, {arm32::pld}};
            for (int i=0; i<0b10; i++) _stage1_cond_insn_uncond[0b1010101 | SET_BITS(i, 3)] = {true, {arm32::pld}};
            _stage1_cond_insn_uncond[0b1010111] = {true, {arm32::clrex}};

            for (int i=0; i<0b10; i++) _stage1_cond_insn_uncond[0b1100001 | SET_BITS(i, 3)] = {true, {arm32::nop}};
            for (int i=0; i<0b10; i++) _stage1_cond_insn_uncond[0b1100101 | SET_BITS(i, 3)] = {true, {arm32::pli, arm32::st_register}};
            for (int i=0; i<0b10; i++) _stage1_cond_insn_uncond[0b1110001 | SET_BITS(i, 3)] = {true, {arm32::pld, arm32::st_register}};
        }
        
        for (int i=0; i<0b100; i++) _stage1_cond_insn_uncond[0b10000100 | SET_BITS(i, 3)] = {true, {arm32::srs}};
        for (int i=0; i<0b100; i++) _stage1_cond_insn_uncond[0b10000110 | SET_BITS(i, 3)] = {true, {arm32::srs}};

        for (int i=0; i<0b100; i++) _stage1_cond_insn_uncond[0b10000001 | SET_BITS(i, 3)] = {true, {arm32::rfe}};
        for (int i=0; i<0b100; i++) _stage1_cond_insn_uncond[0b10000011 | SET_BITS(i, 3)] = {true, {arm32::rfe}};

        for (int i=0; i<0b100000; i++) _stage1_cond_insn_uncond[0b10100000 | SET_BITS(i, 0)] = {true, {arm32::blx}};

        for (int i=0; i<0b10000; i++) _stage1_cond_insn_uncond[0b11000001 | SET_BITS(i, 1)] = {true, {arm32::ldc2, arm32::st_immediate}};

        _stage1_cond_insn_uncond[0b11000100] = {true, {arm32::mcrr2}};
        _stage1_cond_insn_uncond[0b11000101] = {true, {arm32::mrrc2}};

        for (int i=0; i<0b1000; i++) _stage1_cond_insn_uncond[0b11100000 | SET_BITS(i, 1)] = {true, {arm32::mcr2}};
        for (int i=0; i<0b1000; i++) _stage1_cond_insn_uncond[0b11100001 | SET_BITS(i, 1)] = {true, {arm32::mrc2}};
    };
    constexpr decoder_val operator[](uint32_t i) const{
        if (BIT_RANGE(i, 28, 31) == 0b1111) {
            auto predec = _stage1_cond_insn_uncond[BIT_RANGE(i, 20, 27)];
            switch (predec.types.type) {
                case arm32::mcr2:
                case arm32::mrc2:
                    if (BIT_AT(i, 4) == 0b0) {
                        return {true, {arm32::cdp2}};
                    }
                    break;

                case arm32::ldc2:
                    if (BIT_RANGE(i, 16, 19) == 0b1111) {
                        return {true, {arm32::ldc2, arm32::st_literal}};
                    }
                    break;
                case arm32::clrex:
                    switch (BIT_RANGE(i, 4, 7)) {
                        case 0b0100:
                            return {true, {arm32::dsb}};
                        case 0b0101:
                            return {true, {arm32::dmb}};
                        case 0b0110:
                            return {true, {arm32::isb}};
                        default:
                            break;
                    }
                    break;
                case arm32::cps:
                    if (BIT_AT(i, 15) == 0b1) {
                        return {true, {arm32::setend}};
                    }
                    break;
                    
                default:
                    break;
            }
            return predec;
        }else{
            return _stage1_cond_insn_cond[(BIT_RANGE(i, 25, 27) << 1) | BIT_AT(i, 4)];
        }
    }
};


constexpr static const decoder_stage1_arm32 decoder_stage1_arm32;

#pragma mark insn type accessors

uint32_t arm::opcode(){
    return _opcode;
}

uint32_t arm::pc(){
    return _pc;
}

enum arm32::type arm::type(){
    if (_type != unknown) {
        return _type;
    }
    
    decoder_val lookup = decoder_stage1_arm32[_opcode];
    
    if (lookup.isInsn) {
        _type = lookup.types.type;
        _subtype = lookup.types.subtype;
        _supertype = lookup.types.supertype;
    }else if (lookup.next_stage_decoder){
        auto types = lookup.next_stage_decoder(_opcode);
        _type = types.type;
        _subtype = types.subtype;
        _supertype = types.supertype;
    }
    
    return _type;
}

enum arm32::subtype arm::subtype(){
    return _subtype;
}

enum arm32::supertype arm::supertype(){
    return _supertype;
}

#pragma mark cast operators
arm::operator enum type(){
    return type();
}

arm::operator loc_t(){
    return (loc_t)_pc;
}
