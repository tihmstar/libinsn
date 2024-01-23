//
//  insn32.cpp
//  libinsn
//
//  Created by tihmstar on 09.10.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//


#include <libgeneral/macros.h>
#include "../include/libinsn/INSNexception.hpp"

#include "../include/libinsn/arm32/arm32_thumb.hpp"


#ifdef DEBUG
#   include <stdint.h>
static constexpr uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); }
static constexpr uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) % 2; }
static constexpr uint64_t SET_BITS(uint64_t v, int begin) { return ((v)<<(begin));}
static constexpr uint32_t I2(uint32_t v) { return ((v) >> 16);}
static constexpr uint32_t I1(uint32_t v) { return ((v) & 0xffff);}
#else
#   define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1 << ((end)-(begin)+1)) )
#   define BIT_AT(v,pos) ( (v >> pos) % 2 )
#   define SET_BITS(v, begin) (((v)<<(begin)))
#   define I2(i) ((i) >> 16)
#   define I1(i) ((i) & 0xffff)
#endif


using namespace tihmstar::libinsn;
using namespace tihmstar::libinsn::arm32;

thumb::thumb(uint32_t opcode, uint32_t pc)
: _opcode(opcode), _pc(pc), _type(unknown), _subtype(st_general), _supertype(sut_general)
{
    //
}

#pragma mark reference manual helpers
__attribute__((always_inline)) static uint32_t signExtend32(uint32_t v, int vSize){
    uint32_t e = (v & 1 << (vSize-1))>>(vSize-1);
    for (int i=vSize; i<32; i++)
        v |= e << i;
    return v;
}

struct regtypes{
    enum type type;
    enum subtype subtype;
    enum supertype supertype;
};


uint32_t ROR_C(uint32_t unrotated_value, uint32_t shift){
    return ((uint32_t)(unrotated_value >> shift)) | ((uint32_t)(unrotated_value << (32-shift)));
}

std::pair<int32_t, bool> ThumbExpandImm_C(int16_t imm12, bool carry_in){
    if (BIT_RANGE(imm12, 10, 11) == 0b00) {
        switch (BIT_RANGE(imm12, 8, 9)) {
            case 0b00:
                return {BIT_RANGE(imm12, 0, 7),carry_in};
            case 0b01:
            {
                int32_t val = (int32_t)BIT_RANGE(imm12, 0, 7);
                val = (val << 16) | val;
                return {val,carry_in};
            }
            case 0b10:
            {
                int32_t val = (int32_t)BIT_RANGE(imm12, 0, 7);
                val = (val << 24) | (val << 8);
                return {val,carry_in};
            }
            case 0b11:
            {
                int32_t val = (int32_t)BIT_RANGE(imm12, 0, 7);
                val = (val << 24) | (val << 8) | (val << 16) | val;
                return {val,carry_in};
            }

            default:
                reterror("WTF???");
                break;
        }
    }else{
        int32_t unrotated_value = (int32_t)BIT_RANGE(imm12, 0, 6) | 0b10000000;
        return {ROR_C((uint32_t)unrotated_value, (uint32_t)BIT_RANGE(imm12, 7, 11)),carry_in};
    }
}

enum SRType{
    SRType_LSL = 0b00,
    SRType_LSR = 0b01,
    SRType_ASR = 0b10,
    SRType_RRX,
    SRType_ROR
};

std::pair<SRType, int32_t> DecodeImmShift(int8_t type2, int8_t imm5){
    switch (type2) {
        case 0b00:
            return {SRType_LSL, imm5};
        case 0b01:
            return {SRType_LSR, imm5 == 0 ? 32 : imm5};
        case 0b10:
            return {SRType_ASR, imm5 == 0 ? 32 : imm5};
        case 0b11:
            if (imm5 == 0) {
                return {SRType_RRX, 1};
            }else{
                return {SRType_ROR, imm5};
            }
        default:
            reterror("unexpected type 0x%x",type2);
            break;
    }
}


typedef regtypes (*insn_type_test_func)(uint32_t);

struct decoder_val{
    bool isInsn;
    union {
        regtypes types;
        const insn_type_test_func next_stage_decoder;
    };
};

#pragma mark second stage decoders thumb16

constexpr regtypes data_processing_decoder16(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn[(1<<4)]; //4bit
        constexpr decoder_stage2() : _stage2_insn{}
        {
            _stage2_insn[0b0000] = {arm32::and_,arm32::st_register};
            _stage2_insn[0b0001] = {arm32::eor,arm32::st_register};
            _stage2_insn[0b0010] = {arm32::lsl,arm32::st_register};
            _stage2_insn[0b0011] = {arm32::lsr,arm32::st_register};
            _stage2_insn[0b0100] = {arm32::asr,arm32::st_register};
            _stage2_insn[0b0101] = {arm32::adc,arm32::st_register};
            _stage2_insn[0b0110] = {arm32::sbc,arm32::st_register};
            _stage2_insn[0b0111] = {arm32::ror,arm32::st_register};
            _stage2_insn[0b1000] = {arm32::tst,arm32::st_register};
            _stage2_insn[0b1001] = {arm32::rsb,arm32::st_immediate};
            _stage2_insn[0b1010] = {arm32::cmp,arm32::st_register};
            _stage2_insn[0b1011] = {arm32::cmn,arm32::st_register};
            _stage2_insn[0b1100] = {arm32::orr,arm32::st_register};
            _stage2_insn[0b1101] = {arm32::mul,arm32::st_general};
            _stage2_insn[0b1110] = {arm32::bic,arm32::st_register};
            _stage2_insn[0b1111] = {arm32::mvn,arm32::st_register};
        }
        constexpr regtypes operator[](uint8_t i) const{
            return _stage2_insn[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
        
    return decode_table_stage2[BIT_RANGE(i,6,9)];
}

constexpr regtypes special_instructions_decoder16(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn[(1<<4)]; //4bit
        constexpr decoder_stage2() : _stage2_insn{}
        {
            for (int i=0; i<0b100; i++) _stage2_insn[0b0000 | SET_BITS(i,0)] = {arm32::add,arm32::st_register};

            _stage2_insn[0b0100] = {arm32::unknown};//0100 UNPREDICTABLE

            _stage2_insn[0b0101] = {arm32::cmp,arm32::st_register};
            for (int i=0; i<0b10; i++) _stage2_insn[0b0110 | SET_BITS(i,0)] = {arm32::cmp,arm32::st_register};

            for (int i=0; i<0b100; i++) _stage2_insn[0b1000 | SET_BITS(i,0)] = {arm32::mov,arm32::st_register};

            for (int i=0; i<0b10; i++) _stage2_insn[0b1100 | SET_BITS(i,0)] = {arm32::bx,arm32::st_register};
            for (int i=0; i<0b10; i++) _stage2_insn[0b1110 | SET_BITS(i,0)] = {arm32::blx,arm32::st_register};
        }
        constexpr regtypes operator[](uint8_t i) const{
            return _stage2_insn[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
        
    return decode_table_stage2[BIT_RANGE(i,6,9)];
}

constexpr regtypes miscellaneous_decoder16(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn[(1<<7)]; //7bit
        constexpr decoder_stage2() : _stage2_insn{}
        {
            _stage2_insn[0b0110011] = {arm32::cps};

            for (int i=0; i<0b100; i++) _stage2_insn[0b0000000 | SET_BITS(i,0)] = {arm32::add}; //not general add
            for (int i=0; i<0b100; i++) _stage2_insn[0b0000100 | SET_BITS(i,0)] = {arm32::sub}; //not general sub

            for (int i=0; i<0b1000; i++) _stage2_insn[0b0001000 | SET_BITS(i,0)] = {arm32::cbz,arm32::st_general,arm32::sut_branch_imm};

            for (int i=0; i<0b10; i++) _stage2_insn[0b0010000 | SET_BITS(i,0)] = {arm32::sxth};
            for (int i=0; i<0b10; i++) _stage2_insn[0b0010010 | SET_BITS(i,0)] = {arm32::sxtb};

            for (int i=0; i<0b10; i++) _stage2_insn[0b0010100 | SET_BITS(i,0)] = {arm32::uxth};
            for (int i=0; i<0b10; i++) _stage2_insn[0b0010110 | SET_BITS(i,0)] = {arm32::uxtb};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b0011000 | SET_BITS(i,0)] = {arm32::cbz,arm32::st_general,arm32::sut_branch_imm};

            for (int i=0; i<0b10000; i++) _stage2_insn[0b0100000 | SET_BITS(i,0)] = {arm32::push,arm32::st_general,arm32::sut_memory};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b1001000 | SET_BITS(i,0)] = {arm32::cbnz,arm32::st_general,arm32::sut_branch_imm};

            for (int i=0; i<0b10; i++) _stage2_insn[0b1010000 | SET_BITS(i,0)] = {arm32::rev};
            for (int i=0; i<0b10; i++) _stage2_insn[0b1010010 | SET_BITS(i,0)] = {arm32::rev16};
            for (int i=0; i<0b10; i++) _stage2_insn[0b1010110 | SET_BITS(i,0)] = {arm32::revsh};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b1011000 | SET_BITS(i,0)] = {arm32::cbnz,arm32::st_general,arm32::sut_branch_imm};

            for (int i=0; i<0b10000; i++) _stage2_insn[0b1100000 | SET_BITS(i,0)] = {arm32::pop,arm32::st_general,arm32::sut_memory};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b1110000 | SET_BITS(i,0)] = {arm32::bkpt};

            /* ----- THESE MORE DECODING IN A FURTHER STEP ----- */
            for (int i=0; i<0b1000; i++) _stage2_insn[0b1111000 | SET_BITS(i,0)] = {arm32::unknown}; //If-Then, and hints
            
        }
        constexpr regtypes operator[](uint8_t i) const{
            return _stage2_insn[i];
        }
    };

    constexpr const decoder_stage2 decode_table_stage2;

    auto predec = decode_table_stage2[BIT_RANGE(i,5,11)];
    if (predec.type == arm32::unknown) {
        //If-Then, and hints
        
        if (BIT_RANGE(i, 8, 15) != 0b10111111) return {arm32::unknown}; //something went wrong here :/
        
        if (BIT_RANGE(i, 0, 3) != 0b0000) return {arm32::it};
            
        switch (BIT_RANGE(i, 4, 7)) {
            case 0b0000:
                return {arm32::nop};
            case 0b0001:
                return {arm32::yield};
            case 0b0010:
                return {arm32::wfe};
            case 0b0011:
                return {arm32::wfi};
            case 0b0100:
                return {arm32::sev};

            default:
                return {arm32::unknown}; //something went wrong here :/
        }
    }
    
    return predec;
}
    
#pragma mark decoding unit thumb16

struct decoder_stage1_thumb16{
    decoder_val _stage1_insn[0x100]; //8 bit
    constexpr decoder_stage1_thumb16() : _stage1_insn{}
    {
        //Shift (immediate), add, subtract, move, and compare on page A5-6
        {
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b00000 << 1) | SET_BITS(i,0)] = {true, {arm32::lsl,arm32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b00100 << 1) | SET_BITS(i,0)] = {true, {arm32::lsr,arm32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b01000 << 1) | SET_BITS(i,0)] = {true, {arm32::asr,arm32::st_immediate}};

            for (int i=0; i<2; i++) _stage1_insn[(0b01100 << 1) | SET_BITS(i,0)] = {true, {arm32::add,arm32::st_register}};
            for (int i=0; i<2; i++) _stage1_insn[(0b01101 << 1) | SET_BITS(i,0)] = {true, {arm32::sub,arm32::st_register}};

            for (int i=0; i<2; i++) _stage1_insn[(0b01110 << 1) | SET_BITS(i,0)] = {true, {arm32::add,arm32::st_immediate}};
            for (int i=0; i<2; i++) _stage1_insn[(0b01111 << 1) | SET_BITS(i,0)] = {true, {arm32::sub,arm32::st_immediate}};

            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b10000 << 1) | SET_BITS(i,0)] = {true, {arm32::mov,arm32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b10100 << 1) | SET_BITS(i,0)] = {true, {arm32::cmp,arm32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b11000 << 1) | SET_BITS(i,0)] = {true, {arm32::add,arm32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b11100 << 1) | SET_BITS(i,0)] = {true, {arm32::sub,arm32::st_immediate}};
        }

        //Data processing on page A5-7
        {
            for (int i=0; i<4; i++) _stage1_insn[(0b010000 << 2) | SET_BITS(i,0)] = {false, {.next_stage_decoder = data_processing_decoder16}};
        }
        
        //Special data instructions and branch and exchange on page A5-8
        {
            for (int i=0; i<4; i++) _stage1_insn[(0b010001 << 2) | SET_BITS(i,0)] = {false, {.next_stage_decoder = special_instructions_decoder16}};
        }
        
        //Load from Literal Pool, see LDR (literal) on page A6-90
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b010010 << 2) | SET_BITS(i,0)] = {true, {arm32::ldr, arm32::st_literal, arm32::sut_memory}};
        }
        
        //Load/store single data item on page A5-9
        {
            for (int i=0; i<2; i++) _stage1_insn[(0b0101000 << 1) | SET_BITS(i,0)] = {true, {arm32::str,arm32::st_register, arm32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101001 << 1) | SET_BITS(i,0)] = {true, {arm32::strh,arm32::st_register, arm32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101010 << 1) | SET_BITS(i,0)] = {true, {arm32::strb,arm32::st_register, arm32::sut_memory}};

            for (int i=0; i<2; i++) _stage1_insn[(0b0101011 << 1) | SET_BITS(i,0)] = {true, {arm32::ldrsb,arm32::st_register, arm32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101100 << 1) | SET_BITS(i,0)] = {true, {arm32::ldr,arm32::st_register, arm32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101101 << 1) | SET_BITS(i,0)] = {true, {arm32::ldrh,arm32::st_register, arm32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101110 << 1) | SET_BITS(i,0)] = {true, {arm32::ldrb,arm32::st_register, arm32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101111 << 1) | SET_BITS(i,0)] = {true, {arm32::ldrsh,arm32::st_register, arm32::sut_memory}};


            for (int i=0; i<0b1000; i++) _stage1_insn[(0b01100 << 3) | SET_BITS(i,0)] = {true, {arm32::str,arm32::st_immediate, arm32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b01101 << 3) | SET_BITS(i,0)] = {true, {arm32::ldr,arm32::st_immediate, arm32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b01110 << 3) | SET_BITS(i,0)] = {true, {arm32::strb,arm32::st_immediate, arm32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b01111 << 3) | SET_BITS(i,0)] = {true, {arm32::ldrb,arm32::st_immediate, arm32::sut_memory}};

            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10000 << 3) | SET_BITS(i,0)] = {true, {arm32::strh,arm32::st_immediate, arm32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10001 << 3) | SET_BITS(i,0)] = {true, {arm32::ldrh,arm32::st_immediate, arm32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10010 << 3) | SET_BITS(i,0)] = {true, {arm32::str,arm32::st_immediate, arm32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10011 << 3) | SET_BITS(i,0)] = {true, {arm32::ldr,arm32::st_immediate, arm32::sut_memory}};
        }
        
        //Generate PC-relative address, see ADR on page A6-30
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10100 << 3) | SET_BITS(i,0)] = {true, {arm32::adr,arm32::st_general}};
        }
        
        //Generate SP-relative address, see ADD (SP plus immediate) on page A6-26
        {
            for (int i=0; i<0b10101; i++) _stage1_insn[(0b10100 << 3) | SET_BITS(i,0)] = {true, {arm32::add,arm32::st_general}};//not a general add here
        }
        
        //Miscellaneous 16-bit instructions on page A5-10
        {
            for (int i=0; i<0b10000; i++) _stage1_insn[(0b101100 << 2) | SET_BITS(i,0)] = {false, {.next_stage_decoder = miscellaneous_decoder16}};

        }
        
        //Store multiple registers, see STM / STMIA / STMEA on page A6-218
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b110000 << 2) | SET_BITS(i,0)] = {true, {arm32::stm,arm32::st_general, arm32::sut_memory}};
        }
        
        //Load multiple registers, see LDM / LDMIA / LDMFD on page A6-84
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b110010 << 2) | SET_BITS(i,0)] = {true, {arm32::ldm,arm32::st_general, arm32::sut_memory}};
        }
        
        //Conditional branch, and supervisor call
        {
            for (int i=0; i<0b1110; i++) _stage1_insn[0b11010000 | SET_BITS(i,0)] = {true, {arm32::b,arm32::st_general, arm32::sut_branch_imm}};

            _stage1_insn[0b11011110] = {true, {arm32::unknown}}; //Permanently UNDEFINED
            
            _stage1_insn[0b11011111] = {true, {arm32::svc}};
        }
        
        //Unconditional Branch, see B on page A6-40
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b111000 << 2) | SET_BITS(i,0)] = {true, {arm32::b,arm32::st_general, arm32::sut_branch_imm}};
        }
    };
    constexpr decoder_val operator[](uint32_t i) const{
        return _stage1_insn[BIT_RANGE(i, 8, 15)];
    }
};

#pragma mark second stage decoders thumb32

constexpr regtypes load_byte_memory_hints_decoder32(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn_rt[(1<<10)]; //10bit
        constexpr decoder_stage2() : _stage2_insn_rt{}
        {
            //ldrb
            for (int i=0; i<0b1000000; i++) _stage2_insn_rt[0b0100000000 | SET_BITS(i, 2)] = {arm32::ldrb, arm32::st_immediate};
            
            for (int i=0; i<0b100; i++)
                for (int j=0; j<0b100; j++)
                    for (int t=0; t<0b10; t++)
                        _stage2_insn_rt[0b0010010000 | SET_BITS(i, 2) | SET_BITS(j, 5) | SET_BITS(t, 0)] = {arm32::ldrb, arm32::st_immediate};
            
            for (int i=0; i<0b100; i++) _stage2_insn_rt[0b0011000000 | SET_BITS(i, 2)] = {arm32::ldrb, arm32::st_immediate};

            for (int i=0; i<0b100; i++) for (int t=0; t<0b10; t++) _stage2_insn_rt[0b0011100000 | SET_BITS(i, 2) | SET_BITS(t, 0)] = {arm32::ldrbt};

            for (int i=0; i<0b10000000; i++) _stage2_insn_rt[0b0000000010 | SET_BITS(i, 2)] = {arm32::ldrb, arm32::st_literal};

            _stage2_insn_rt[0b0000000000] = {arm32::ldrb, arm32::st_register};

            //ldrsb
            for (int i=0; i<0b1000000; i++) _stage2_insn_rt[0b1100000000 | SET_BITS(i, 2)] = {arm32::ldrsb, arm32::st_immediate};

            for (int i=0; i<0b100; i++)
                for (int j=0; j<0b100; j++)
                    for (int t=0; t<0b10; t++)
                        _stage2_insn_rt[0b1010010000 | SET_BITS(i, 2) | SET_BITS(j, 5) | SET_BITS(t, 0)] = {arm32::ldrsb, arm32::st_immediate};

            for (int i=0; i<0b100; i++) _stage2_insn_rt[0b1011000000 | SET_BITS(i, 2)] = {arm32::ldrsb, arm32::st_immediate};

            for (int i=0; i<0b100; i++) for (int t=0; t<0b10; t++) _stage2_insn_rt[0b1011100000 | SET_BITS(i, 2) | SET_BITS(t, 0)] = {arm32::ldrsbt};

            for (int i=0; i<0b10000000; i++) _stage2_insn_rt[0b1000000010 | SET_BITS(i, 2)] = {arm32::ldrsb, arm32::st_literal};

            _stage2_insn_rt[0b1000000000] = {arm32::ldrb, arm32::st_register};
            
            //pld
            for (int i=0; i<0b1000000; i++) _stage2_insn_rt[0b0100000001 | SET_BITS(i, 2)] = {arm32::pld, arm32::st_immediate};
            for (int i=0; i<0b100; i++) _stage2_insn_rt[0b0011000001 | SET_BITS(i, 2)] = {arm32::pld, arm32::st_immediate};
            for (int i=0; i<0b10000000; i++) _stage2_insn_rt[0b0000000011 | SET_BITS(i, 2)] = {arm32::pld, arm32::st_immediate};
            _stage2_insn_rt[0b0000000001] = {arm32::pld, arm32::st_register};

            //pli
            for (int i=0; i<0b1000000; i++) _stage2_insn_rt[0b1100000001 | SET_BITS(i, 2)] = {arm32::pli, arm32::st_immediate};
            for (int i=0; i<0b100; i++) _stage2_insn_rt[0b1011000001 | SET_BITS(i, 2)] = {arm32::pli, arm32::st_immediate};
            for (int i=0; i<0b10000000; i++) _stage2_insn_rt[0b1000000011 | SET_BITS(i, 2)] = {arm32::pli, arm32::st_immediate};
            _stage2_insn_rt[0b1000000001] = {arm32::pli, arm32::st_register};
        }
        constexpr regtypes operator[](uint16_t i) const{
            return _stage2_insn_rt[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
    uint16_t lval = (BIT_RANGE(I1(i), 7, 8) << 6) | BIT_RANGE(I2(i), 6, 11);
    lval = (lval << 2) | ((BIT_RANGE(I1(i), 0, 3) == 0b1111) << 1) | ((BIT_RANGE(I2(i), 12, 15) == 0b1111) << 0);
    return decode_table_stage2[lval];
}

constexpr regtypes load_halfword_unallocated_memory_hints_decoder32(uint32_t i){
    struct decoder_stage2{
        regtypes _stage2_insn_rt[(1<<9)]; //9bit
        constexpr decoder_stage2() : _stage2_insn_rt{}
        {
            //ldrh
            for (int i=0; i<0b1000000; i++) _stage2_insn_rt[0b010000000 | SET_BITS(i, 1)] = {arm32::ldrh, arm32::st_immediate};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b100; j++) _stage2_insn_rt[0b001001000 | SET_BITS(i, 1) | SET_BITS(j, 4)] = {arm32::ldrh, arm32::st_immediate};
            for (int i=0; i<0b100; i++) _stage2_insn_rt[0b001100000 | SET_BITS(i, 1)] = {arm32::ldrh, arm32::st_immediate};
            
            for (int i=0; i<0b100; i++) _stage2_insn_rt[0b001110000 | SET_BITS(i, 1)] = {arm32::ldrht};
            for (int i=0; i<0b10000000; i++) _stage2_insn_rt[0b000000001 | SET_BITS(i, 1)] = {arm32::ldrh, arm32::st_literal};
            _stage2_insn_rt[0b000000000] = {arm32::ldrh, arm32::st_register};

            //ldrsh
            for (int i=0; i<0b1000000; i++) _stage2_insn_rt[0b110000000 | SET_BITS(i, 1)] = {arm32::ldrsh, arm32::st_immediate};
            for (int i=0; i<0b100; i++) for (int j=0; j<0b100; j++) _stage2_insn_rt[0b101001000 | SET_BITS(i, 1) | SET_BITS(j, 4)] = {arm32::ldrsh, arm32::st_immediate};
            for (int i=0; i<0b100; i++) _stage2_insn_rt[0b101100000 | SET_BITS(i, 1)] = {arm32::ldrsh, arm32::st_immediate};

            for (int i=0; i<0b100; i++) _stage2_insn_rt[0b101110000 | SET_BITS(i, 1)] = {arm32::ldrsht};
            for (int i=0; i<0b10000000; i++) _stage2_insn_rt[0b100000001 | SET_BITS(i, 1)] = {arm32::ldrsh, arm32::st_literal};
            _stage2_insn_rt[0b100000000] = {arm32::ldrsh, arm32::st_register};
        }
        constexpr regtypes operator[](uint16_t i) const{
            return _stage2_insn_rt[i];
        }
    };
        
    constexpr const decoder_stage2 decode_table_stage2;
    uint16_t lval = (BIT_RANGE(I1(i), 7, 8) << 2) | BIT_RANGE(I2(i), 6, 11);
    lval = (lval << 1) | (BIT_RANGE(I1(i), 0, 3) == 0b1111);
    return decode_table_stage2[lval];
}

constexpr regtypes load_word_decoder32(uint32_t i){
    if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
        return {arm32::ldr, arm32::st_literal};
    }else if (BIT_AT(I1(i), 7)){
        return {arm32::ldr, arm32::st_immediate};
    }else if (BIT_RANGE(I2(i), 6, 11) == 0){
        return {arm32::ldr, arm32::st_register};
    }else if (BIT_RANGE(I2(i), 8, 11) == 0b1110){
        return {arm32::ldrt};
    }else{
        return {arm32::ldr, arm32::st_immediate};
    }
}
    
#pragma mark decoding unit thumb32

struct decoder_stage1_thumb32{
    decoder_val _stage1_insn[(1<<9) - 0b010000000]; //9 bit but no values lower than b010000000
    constexpr decoder_stage1_thumb32() : _stage1_insn{}
    {
        //Load/store multiple on page A5-20
        {
            _stage1_insn[(0b010001000) - 0b010000000] = {true, {arm32::stm,arm32::st_general, arm32::sut_memory}};
            
            //possibly POP
            _stage1_insn[(0b010001011) - 0b010000000] = {true, {arm32::ldm,arm32::st_general, arm32::sut_memory}};
            
            //possibly PUSH
            _stage1_insn[(0b010010010) - 0b010000000] = {true, {arm32::stmdb,arm32::st_general, arm32::sut_memory}};

            _stage1_insn[(0b010010000) - 0b010000000] = {true, {arm32::stmdb,arm32::st_general, arm32::sut_memory}};
        }
        
        //Load/store dual or exclusive, table branch on page A5-21
        {
            _stage1_insn[(0b010000100) - 0b010000000] = {true, {arm32::strex,arm32::st_register_extended, arm32::sut_memory}};
            _stage1_insn[(0b010000101) - 0b010000000] = {true, {arm32::ldrex,arm32::st_register_extended, arm32::sut_memory}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010000110 | SET_BITS(i, 3)) - 0b010000000] = {true, {arm32::strd,arm32::st_general, arm32::sut_memory}};
            for (int i=0; i<0b10; i++)
                for (int j=0; j<0b10; j++) _stage1_insn[(0b010010100 | SET_BITS(i, 3) | SET_BITS(j, 1)) - 0b010000000] = {true, {arm32::strd,arm32::st_general, arm32::sut_memory}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010000111 | SET_BITS(i, 3)) - 0b010000000] = {true, {arm32::ldrd,arm32::st_general, arm32::sut_memory}};
            for (int i=0; i<0b10; i++)
                for (int j=0; j<0b10; j++) _stage1_insn[(0b010010101 | SET_BITS(i, 3) | SET_BITS(j, 1)) - 0b010000000] = {true, {arm32::ldrd,arm32::st_general, arm32::sut_memory}};
            
            //possibly STREXH or undefined
            _stage1_insn[(0b010001100) - 0b010000000] = {true, {arm32::strexb,arm32::st_register_extended, arm32::sut_memory}};

            //possibly TTH or LDREXB or LDREXH or undefined
            _stage1_insn[(0b010001101) - 0b010000000] = {true, {arm32::ttb}};
        }
        
        //Data processing (shifted register) on page A5-26
        {
            //possibly TST or undefined
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010100000 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::and_,arm32::st_register}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010100010 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::bic,arm32::st_register}};

            //possibly (Move register and immediate shifts)
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010100100 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::orr,arm32::st_register}};

            //possibly MVN
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010100110 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::orn,arm32::st_register}};

            //possibly TEQ or undefined
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010101000 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::eor,arm32::st_register}};

            //possibly TEQ or undefined
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010110000 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::add,arm32::st_register}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010110100 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::adc,arm32::st_register}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010110110 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::sbc,arm32::st_register}};

            //possibly CMP or undefined
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010111010 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::sub,arm32::st_register}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010111100 | SET_BITS(i, 0)) - 0b010000000] = {true, {arm32::rsb,arm32::st_register}};
        }
        
        //Coprocessor instructions on page A5-32
        {
            for (int i=1; i<0b10000; i++) _stage1_insn[(0b011000000 | SET_BITS(i, 1)) - 0b010000000] = {true, {arm32::stc, arm32::st_immediate, arm32::sut_memory}};
            for (int i=1; i<0b10000; i++) _stage1_insn[(0b111000000 | SET_BITS(i, 1)) - 0b010000000] = {true, {arm32::stc2, arm32::st_immediate, arm32::sut_memory}};

            for (int i=1; i<0b10000; i++) _stage1_insn[(0b011000001 | SET_BITS(i, 1)) - 0b010000000] = {true, {arm32::ldc, arm32::st_immediate, arm32::sut_memory}};
            for (int i=1; i<0b10000; i++) _stage1_insn[(0b111000001 | SET_BITS(i, 1)) - 0b010000000] = {true, {arm32::ldc2, arm32::st_immediate, arm32::sut_memory}};


            //IMPORTANT:
            //MCRR(2) and MRRC(2) need to follow stc/ldc, because they overwrite some instructions space

            _stage1_insn[0b011000100 - 0b010000000] = {true, {arm32::mcrr}};
            _stage1_insn[0b111000100 - 0b010000000] = {true, {arm32::mcrr2}};

            _stage1_insn[0b011000101 - 0b010000000] = {true, {arm32::mrrc}};
            _stage1_insn[0b011000101 - 0b010000000] = {true, {arm32::mrrc2}};


            for (int i=1; i<0b1000; i++) _stage1_insn[(0b011100000 | SET_BITS(i, 1)) - 0b010000000] = {true, {arm32::mcr}};
            for (int i=1; i<0b1000; i++) _stage1_insn[(0b111100000 | SET_BITS(i, 1)) - 0b010000000] = {true, {arm32::mcr2}};

            for (int i=1; i<0b1000; i++) _stage1_insn[(0b011100001 | SET_BITS(i, 1)) - 0b010000000] = {true, {arm32::mrc}};
            for (int i=1; i<0b1000; i++) _stage1_insn[(0b111100001 | SET_BITS(i, 1)) - 0b010000000] = {true, {arm32::mrc2}};
        }

        //Data processing (modified immediate) on page A5-14
        {
            //needs I2(15) == 0 check!
            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100000000 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::and_, arm32::st_immediate}};

            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100000010 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::bic, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100000100 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::orr, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100000110 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::orn, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100001000 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::eor, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100010000 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::add, arm32::st_immediate}};

            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100010100 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::adc, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100010110 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::sbc, arm32::st_immediate}};

            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100011010 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::sub, arm32::st_immediate}};

            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b100011100 | SET_BITS(i, 6) | SET_BITS(j, 0)) - 0b010000000] = {true, {arm32::rsb, arm32::st_immediate}};
        }

        //Data processing (plain binary immediate) on page A5-17
        {
            //needs I2(15) == 0 check!
            for (int i=0; i<0b10; i++) _stage1_insn[(0b100100000 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::add, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) _stage1_insn[(0b100100100 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::mov, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) _stage1_insn[(0b100101010 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::sub, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) _stage1_insn[(0b100101100 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::movt, arm32::st_immediate}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b100110000 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::ssat, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) _stage1_insn[(0b100110010 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::ssat, arm32::st_immediate}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b100110100 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::sbfx, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) _stage1_insn[(0b100110110 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::bfi, arm32::st_immediate}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b100111000 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::usat, arm32::st_immediate}};
            for (int i=0; i<0b10; i++) _stage1_insn[(0b100111010 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::usat, arm32::st_immediate}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b100111100 | SET_BITS(i, 6)) - 0b010000000] = {true, {arm32::ubfx, arm32::st_immediate}};
        }

        //Branches and miscellaneous control on page A5-18
        {
            //this is done in post processing predec
        }

        //Store single data item on page A5-25
        {
            _stage1_insn[(0b110001000) - 0b010000000] = {true, {arm32::strb, arm32::st_immediate, arm32::sut_memory}};
            //possibly arm32::strb, arm32::st_immediate
            _stage1_insn[(0b110000000) - 0b010000000] = {true, {arm32::strb, arm32::st_register, arm32::sut_memory}};

            _stage1_insn[(0b110001010) - 0b010000000] = {true, {arm32::strh, arm32::st_immediate, arm32::sut_memory}};
            //possibly arm32::strh, arm32::st_immediate
            _stage1_insn[(0b110000010) - 0b010000000] = {true, {arm32::strh, arm32::st_register, arm32::sut_memory}};

            _stage1_insn[(0b110001100) - 0b010000000] = {true, {arm32::str, arm32::st_immediate, arm32::sut_memory}};
            //possibly arm32::str, arm32::st_immediate
            _stage1_insn[(0b110000100) - 0b010000000] = {true, {arm32::str, arm32::st_register, arm32::sut_memory}};
        }

        //Load byte, memory hints on page A5-24
        {
            for (int i=0; i<0b100; i++) _stage1_insn[(0b110000001 | SET_BITS(i,3)) - 0b010000000] = {false, {.next_stage_decoder = load_byte_memory_hints_decoder32}};
        }

        //Load halfword, unallocated memory hints on page A5-23
        {
            for (int i=0; i<0b100; i++) _stage1_insn[(0b110000011 | SET_BITS(i,3)) - 0b010000000] = {false, {.next_stage_decoder = load_halfword_unallocated_memory_hints_decoder32}};
        }

        //Load word on page A5-22
        {
            for (int i=0; i<0b10; i++) _stage1_insn[(0b110000101 | SET_BITS(i,3)) - 0b010000000] = {false, {.next_stage_decoder = load_word_decoder32}};
        }

        //Data processing (register) on page A5-28
        {
            _stage1_insn[(0b110100000) - 0b010000000] = {true, {arm32::sxth}};
            _stage1_insn[(0b110100001) - 0b010000000] = {true, {arm32::uxth}};

            _stage1_insn[(0b110100100) - 0b010000000] = {true, {arm32::sxtb}};
            _stage1_insn[(0b110100101) - 0b010000000] = {true, {arm32::uxtb}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b110100010 | SET_BITS(i,0)) - 0b010000000]= {true, {arm32::lsr, arm32::st_register}};
            for (int i=0; i<0b10; i++) _stage1_insn[(0b110100110 | SET_BITS(i,0)) - 0b010000000]= {true, {arm32::ror, arm32::st_register}};

            _stage1_insn[(0b110101011) - 0b010000000] = {true, {arm32::clz}};

            //possibly rev16, rbit, revsh
            _stage1_insn[(0b110101001) - 0b010000000] = {true, {arm32::rev}};
        }

        //Multiply, and multiply accumulate on page A5-30
        {
            //possibly mla, mul
            _stage1_insn[(0b110110000) - 0b010000000] = {true, {arm32::mls}};
        }

        //Long multiply, long multiply accumulate, and divide on page A5-31
        {
            _stage1_insn[(0b110111000) - 0b010000000] = {true, {arm32::smull}};
            _stage1_insn[(0b110111001) - 0b010000000] = {true, {arm32::sdiv}};
            _stage1_insn[(0b110111010) - 0b010000000] = {true, {arm32::umull}};
            _stage1_insn[(0b110111011) - 0b010000000] = {true, {arm32::udiv}};
            _stage1_insn[(0b110111100) - 0b010000000] = {true, {arm32::smlal}};
            _stage1_insn[(0b110111110) - 0b010000000] = {true, {arm32::umlal}};
        }
    };
    constexpr decoder_val operator[](uint32_t i) const{
        auto predec = _stage1_insn[BIT_RANGE(I1(i), 4, 12) - 0b010000000];
                
        if (BIT_RANGE(I1(i), 11, 12) == 0b10 && BIT_AT(I2(i), 15) == 1) {
            //re-process, this instruction is branch!
            //Branches and miscellaneous control on page A5-18
            
            switch (BIT_RANGE(I2(i), 12, 14)) {
                case 0b111:
                case 0b101:
                    return {true, {arm32::bl, arm32::st_general, arm32::sut_branch_imm}};
                
                case 0b110:
                case 0b100:
                    return {true, {arm32::blx, arm32::st_general, arm32::sut_branch_imm}};

                case 0b001:
                case 0b011:
                    return {true, {arm32::b, arm32::st_general, arm32::sut_branch_imm}};
                
                case 0b000:
                case 0b010:
                {
                    switch (BIT_RANGE(I2(i), 4, 10)) {
                        case 0b0111110:
                        case 0b0111111:
                            return {true, {arm32::mrs}};

                        case 0b0111000:
                        case 0b0111001:
                            return {true, {arm32::msr}};

                        case 0b0111010:
                        {
                            //hint instructions
                            switch (BIT_RANGE(I2(i), 0, 10)) {
                                case 0b00000000000:
                                    return {true, {arm32::nop}};
                                case 0b00000000001:
                                    return {true, {arm32::yield}};
                                case 0b00000000010:
                                    return {true, {arm32::wfe}};
                                case 0b00000000011:
                                    return {true, {arm32::wfi}};
                                case 0b00000000100:
                                    return {true, {arm32::sev}};

                                case 0b11110000:
                                case 0b11110001:
                                case 0b11110010:
                                case 0b11110011:
                                case 0b11110100:
                                case 0b11110101:
                                case 0b11110110:
                                case 0b11110111:
                                case 0b11111000:
                                case 0b11111001:
                                case 0b11111010:
                                case 0b11111011:
                                case 0b11111100:
                                case 0b11111101:
                                case 0b11111110:
                                case 0b11111111:
                                    return {true, {arm32::dbg}};

                                default:
                                    return {true,{arm32::unknown}};
                            }
                            break;
                        }
                            
                        case 0b0111011:
                        {
                            //Miscellaneous control instructions
                            switch (BIT_RANGE(I2(i), 4, 7)) {
                                case 0b0010:
                                    return {true,{arm32::clrex}};
                                case 0b0100:
                                    return {true,{arm32::dsb}};
                                case 0b0101:
                                    return {true,{arm32::dmb}};
                                case 0b0110:
                                    return {true,{arm32::isb}};
                                default:
                                    return {true,{arm32::unknown}};
                            }
                            break;
                        }
                            
                        default:
                            return {true, {arm32::bcond, arm32::st_general, arm32::sut_branch_imm}};
                    }
                }

                default:
                    return {true,{arm32::unknown}};
            }
        }
        
        if (!predec.isInsn) {
            return predec;
        }
        
        switch (predec.types.type) {
            case arm32::mls:
                if (BIT_RANGE(I2(i), 4, 5) == 0) {
                    if (BIT_RANGE(I2(i), 12, 15) == 0b1111) {
                        return {true, {arm32::mul}};
                    }else{
                        return {true, {arm32::mla}};
                    }
                }
                break;
            case arm32::rev:
                switch (BIT_RANGE(I2(i), 4, 5)) {
                    case 0b00:
                        return {true, {arm32::rev}};
                    case 0b01:
                        return {true, {arm32::rev16}};
                    case 0b10:
                        return {true, {arm32::rbit}};
                    case 0b11:
                        return {true, {arm32::revsh}};
                    default://should never be reached
                        return {true, {arm32::unknown}};
                }
                break;
                
            case arm32::sxtb:
            case arm32::uxtb:
                if (BIT_RANGE(I2(i), 4, 7) == 0) {
                    return {true, {arm32::asr, arm32::st_register}};;
                }
                break;

            case arm32::sxth:
            case arm32::uxth:
                if (BIT_RANGE(I2(i), 4, 7) == 0) {
                    return {true, {arm32::lsl, arm32::st_register}};;
                }
                break;
                
            case arm32::str:
                if (BIT_RANGE(I1(i), 4, 7) == 0b010) {
                    if (BIT_AT(I2(i), 11)) {
                        return {true, {arm32::str, arm32::st_immediate, arm32::sut_memory}};
                    }else{
                        return {true, {arm32::str, arm32::st_register, arm32::sut_memory}};
                    }
                }
                break;
                
            case arm32::strh:
                if (BIT_RANGE(I1(i), 4, 7) == 0b001) {
                    if (BIT_AT(I2(i), 11)) {
                        return {true, {arm32::strh, arm32::st_immediate, arm32::sut_memory}};
                    }else{
                        return {true, {arm32::strh, arm32::st_register, arm32::sut_memory}};
                    }
                }
                break;
                
            case arm32::strb:
                if (BIT_RANGE(I1(i), 4, 7) == 0b000) {
                    if (BIT_AT(I2(i), 11)) {
                        return {true, {arm32::strb, arm32::st_immediate, arm32::sut_memory}};
                    }else{
                        return {true, {arm32::strb, arm32::st_register, arm32::sut_memory}};
                    }
                }
                break;
                
            case arm32::bfi:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    return {true, {arm32::bfc}};
                }
                break;
            
            case arm32::mcr:
            case arm32::mcr2:
            case arm32::mrc:
            case arm32::mrc2:
                if (BIT_AT(I2(i), 4) == 0){
                    if (BIT_AT(I1(i), 12) == 0){
                        return {true, {arm32::cdp}};
                    }else{
                        return {true, {arm32::cdp2}};
                    }
                }
                break;

            case arm32::ldc:
            case arm32::ldc2:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    return {true, {predec.types.type, arm32::st_literal, predec.types.supertype}};
                }
                break;
            case arm32::ldm:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1101) {
                    return {true, {arm32::pop}};
                }
                break;
            case arm32::stmdb:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1101) {
                    return {true, {arm32::push}};
                }
                break;
            case arm32::strexb:
                if (BIT_RANGE(I2(i), 4, 7) == 0b0101) {
                    return {true, {arm32::strexh,arm32::st_register_extended, arm32::sut_memory}};
                }else if (BIT_RANGE(I2(i), 4, 7) != 0b0100){
                    return {true, {arm32::unknown}};
                }
            case arm32::ttb:
                if (BIT_RANGE(I2(i), 4, 7) == 0b0101) {
                    return {true, {arm32::tth}};
                }else if (BIT_RANGE(I2(i), 4, 7) == 0b0100){
                    return {true, {arm32::ldrexb}};
                }else if (BIT_RANGE(I2(i), 4, 7) == 0b0101){
                    return {true, {arm32::ldrexh}};
                }else if (BIT_RANGE(I2(i), 4, 7) != 0b0100){
                    return {true, {arm32::unknown}};
                }
            case arm32::and_:
                if (BIT_RANGE(I2(i), 8, 11) == 0b1111) {
                    if (BIT_AT(I1(i), 4) == 1) {
                        return {true, {arm32::tst, predec.types.subtype}};
                    }else{
                        return {true, {arm32::unknown}};
                    }
                }
            case arm32::orr:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    //(Move register and immediate shifts)
                    switch (BIT_RANGE(I2(i), 4, 5)) {
                        case 0b00:
                            if (BIT_RANGE(I2(i), 12, 14) | BIT_RANGE(I2(i), 6, 7)) {
                                return {true, {arm32::lsl,arm32::st_immediate}};
                            }else{
                                return {true, {arm32::mov,predec.types.subtype}};
                            }
                        case 0b01:
                            return {true, {arm32::lsr,arm32::st_immediate}};
                        case 0b10:
                            return {true, {arm32::asr,arm32::st_immediate}};
                        case 0b11:
                            if (BIT_RANGE(I2(i), 12, 14) | BIT_RANGE(I2(i), 6, 7)) {
                                return {true, {arm32::ror,arm32::st_immediate}};
                            }else{
                                return {true, {arm32::rrx}};
                            }
                    }
                }
            case arm32::orn:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    return {true, {arm32::mvn, predec.types.subtype}};
                }
                break;
            case arm32::eor:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    if (BIT_AT(I1(i), 4) == 1) {
                        return {true, {arm32::teq, predec.types.subtype}};
                    }else{
                        return {true, {arm32::unknown}};
                    }
                }
            case arm32::add:
                if (BIT_RANGE(I1( i | SET_BITS(1, 10) ), 11, 12) == 0b101100000 && BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    return {true, {arm32::adr}};
                }
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    if (BIT_AT(I1(i), 4) == 1) {
                        return {true, {arm32::cmn, predec.types.subtype}};
                    }else{
                        return {true, {arm32::unknown}};
                    }
                }
            case arm32::sub:
                if (BIT_RANGE(I1( i | SET_BITS(1, 10) ), 4, 12) == 0b101101010 && BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    return {true, {arm32::adr}};
                }
                if (BIT_RANGE(I2(i), 8, 11) == 0b1111) {
                    if (BIT_AT(I1(i), 4) == 1) {
                        return {true, {arm32::cmp, predec.types.subtype}};
                    }else{
                        return {true, {arm32::unknown}};
                    }
                }
            default:
                return predec;
        }

        return predec;
    }
};

constexpr static const decoder_stage1_thumb16 decode_table_stage1_thumb16;
constexpr static const decoder_stage1_thumb32 decode_table_stage1_thumb32;


#pragma mark insn type accessors

uint32_t thumb::opcode(){
    return _opcode;
}

uint32_t thumb::pc(){
    return _pc;
}

enum arm32::cputype thumb::cputype(){
    return arm32::cputype::cpu_thumb;
}

uint8_t thumb::insnsize() const{
    return (BIT_RANGE(_opcode, 11, 15) > 0b11100) ? 4 : 2;
}


enum arm32::type thumb::type(){
    if (_type != unknown) {
        return _type;
    }
    
    decoder_val lookup = {};
    
    if (BIT_RANGE(_opcode, 11, 15) > 0b11100) {
        lookup = decode_table_stage1_thumb32[_opcode];
    }else{
        lookup = decode_table_stage1_thumb16[_opcode];
    }
    
    if (lookup.isInsn) {
        _type = lookup.types.type;
        _subtype = lookup.types.subtype;
        _supertype = lookup.types.supertype;
    }else if (lookup.next_stage_decoder){
        auto types = lookup.next_stage_decoder(_opcode);
        _type = types.type;
        _subtype = types.subtype;
        _supertype = types.supertype;
    }else{
#ifdef XCODE
        debug("Failed to decode opcode 0x%08x",_opcode);
        reterror("Failed to decode opcode 0x%08x",_opcode);
#endif
    }
    
    return _type;
}

enum arm32::subtype thumb::subtype(){
    if (_type == unknown) type();
    return _subtype;
}

enum arm32::supertype thumb::supertype(){
    if (_type == unknown) type();
    return _supertype;
}


int32_t thumb::imm(){
    switch (insnsize()) {
        case 2:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get imm value of unknown instruction");
                    break;
                case lsl:
                case lsr:
                case asr:
                    return (int32_t)BIT_RANGE(_opcode, 6,10);
                case add:
                case sub:
                {
                    if (BIT_RANGE(_opcode, 13,15) == 0b000) {
                        return (int32_t)BIT_RANGE(_opcode,6,8); //T1 encoding
                    }else if (BIT_RANGE(_opcode, 11,15) == 0b10101){
                        //T1 SP plus immediate
                        return (int32_t)BIT_RANGE(_opcode,0,7)<<2;
                    }else if (BIT_RANGE(_opcode, 7,15) == 0b101100000){
                        //T2 SP plus immediate
                        return (int32_t)BIT_RANGE(_opcode,0,6)<<2;
                    }else{
                        return (int32_t)BIT_RANGE(_opcode,0,7); //T2 encoding
                    }
                }
                case cmp:
                    return (int32_t)BIT_RANGE(_opcode,0,7); //T1 encoding
                case mov:
                    retassure(subtype() == st_immediate, "Bad subtype for mov");
                    return (int32_t)BIT_RANGE(_opcode,0,7); //T1 encoding
                case ldr:
                case str:
                    if (subtype() == st_literal) {
                        return _pc + (4 >> ((_pc>>1) & 1)) + (int32_t)(BIT_RANGE(_opcode,0,7)<<2); //T1 encoding
                    }else if (subtype() == st_immediate) {
                        if (BIT_RANGE(_opcode, 11, 15) == 0b01101) {
                            return (int32_t)BIT_RANGE(_opcode, 6, 10) << 2;
                        } else if (BIT_RANGE(_opcode, 12, 15) == 0b1001 /* T2 */) {
                            return (int32_t)BIT_RANGE(_opcode, 0, 7) << 2;
                        }else{
                            reterror("unimplemented");
                        }
                    }else{
                        reterror("ldr non-literal not implemented");
                    }
                    
                case b:
                case bcond:
                    if (BIT_RANGE(_opcode, 12, 15) == 0b1101) {
                        //T1 encoding
                        return _pc + 4 + signExtend32((int32_t)BIT_RANGE(_opcode, 0, 7)<<1,9);
                    }else{
                        //T2 encoding
                        return _pc + 4 + signExtend32((int32_t)BIT_RANGE(_opcode, 0, 10)<<1,12);
                    }
                case cbz:
                case cbnz:
                {
                    int32_t val = 0;
                    val = (int32_t)(BIT_AT(_opcode, 9));
                    val = (int32_t)((val<<5) | BIT_RANGE(_opcode, 3, 7));
                    return _pc + 4 + (val << 1);
                }
                default:
                    reterror("failed to get imm value for insn size=2");
                    break;
            }
        }
        break;

        case 4:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get imm value of unknown instruction");
                    break;
                case ldr:
                    if (subtype() == st_literal) {
                        if (BIT_AT(I1(_opcode), 7)) {
                            //add
                            return (_pc & ~3) + (int32_t)(BIT_RANGE(I2(_opcode),0,11)) + 4; //T2 encoding
                        }else{
                            //sub
                            return (_pc & ~3) - (int32_t)(BIT_RANGE(I2(_opcode),0,11)) + 4; //T2 encoding
                        }
                    }else{
                        reterror("ldr non-literal not implemented");
                    }
                case bl:
                case blx:
                {
                    uint32_t i_S = (uint32_t)BIT_AT(I1(_opcode), 10);
                    uint32_t i_I1 = !(BIT_AT(I2(_opcode), 13) ^ i_S);
                    uint32_t i_I2 = !(BIT_AT(I2(_opcode), 11) ^ i_S);
                    uint32_t imm = 0;
                    if (BIT_AT(I2(_opcode), 12)) {
                        //T1 encoding
                        imm = (uint32_t)(BIT_RANGE(I1(_opcode), 0, 9) << 12) | (BIT_RANGE(I2(_opcode), 0, 10) << 1);
                    }else{
                        //T2 encoding
                        imm = ((uint32_t)(BIT_RANGE(I1(_opcode), 0, 9) << 11) | (BIT_RANGE(I2(_opcode), 1, 10) << 1)) << 1;
                    }
                    return _pc + 4 + signExtend32((i_S << 24) | (i_I1 << 23) | (i_I2 << 22) | imm, 25);
                }
                    
                case mov:
                    if (subtype() == st_immediate) {
                        if (!BIT_AT(I1(_opcode),9)) {
                            //T2 encoding
                            int32_t val = 0;
                            val = (int32_t)(BIT_AT(I1(_opcode), 10));
                            val = (int32_t)((val<<3) | BIT_RANGE(I2(_opcode), 12, 14));
                            val = (int32_t)((val<<8) | BIT_RANGE(I2(_opcode), 0, 7));
                            return ThumbExpandImm_C(val,0).first;
                        }else{
                            //T3 encoding
                            int32_t val = 0;
                            val = (int32_t)(BIT_RANGE(I1(_opcode), 0, 3));
                            val = (int32_t)((val<<1) | BIT_AT(I1(_opcode), 10));
                            val = (int32_t)((val<<3) | BIT_RANGE(I2(_opcode), 12, 14));
                            val = (int32_t)((val<<8) | BIT_RANGE(I2(_opcode), 0, 7));
                            return val;
                        }
                    }else{
                        reterror("unimplemeted");
                    }
                    break;
                case movt:
                    if (subtype() == st_immediate) {
                        int32_t val = 0;
                        val = (int32_t)(BIT_RANGE(I1(_opcode), 0, 3));
                        val = (int32_t)((val<<1) | BIT_AT(I1(_opcode), 10));
                        val = (int32_t)((val<<3) | BIT_RANGE(I2(_opcode), 12, 14));
                        val = (int32_t)((val<<8) | BIT_RANGE(I2(_opcode), 0, 7));
                        return (val<<16);
                    }else{
                        reterror("bad subtype");
                    }
                case orr:
                    if (subtype() == st_immediate) {
                        int32_t val = 0;
                        val = (int32_t)(BIT_AT(I1(_opcode), 10));
                        val = (int32_t)((val<<3) | BIT_RANGE(I2(_opcode), 12, 14));
                        val = (int32_t)((val<<8) | BIT_RANGE(I2(_opcode), 0, 7));
                        return ThumbExpandImm_C(val,0).first;
                    }else{
                        reterror("unimplemented");
                    }
                    
                case b:
                {
                    uint32_t i_S = (uint32_t)BIT_AT(I1(_opcode), 10);
                    uint32_t i_I1 = !(BIT_AT(I2(_opcode), 13) ^ i_S);
                    uint32_t i_I2 = !(BIT_AT(I2(_opcode), 11) ^ i_S);
                    uint32_t imm = 0;
                    //T4 encoding
                    imm = (uint32_t)((BIT_RANGE(I1(_opcode), 0, 9) << 12) | ((BIT_RANGE(I2(_opcode), 0, 10) << 1)));
                    return _pc + 4 + signExtend32((i_S << 24) | (i_I1 << 23) | (i_I2 << 22) | imm, 25);
                }
                case bcond:
                    //T3 encoding
                    return _pc + 4 + signExtend32((uint32_t)((BIT_RANGE(I1(_opcode), 0, 5) << 12) | ((BIT_RANGE(I2(_opcode), 0, 10) << 1))), 17);

                case tst:
                {
                    int32_t val = 0;
                    val = (int32_t)(BIT_AT(I1(_opcode), 10));
                    val = (int32_t)((val<<3) | BIT_RANGE(I2(_opcode), 12, 14));
                    val = (int32_t)((val<<8) | BIT_RANGE(I2(_opcode), 0, 7));
                    return ThumbExpandImm_C(val,0).first;
                }
                    
                case cmp:
                    if (subtype() == st_immediate) {
                        int32_t val = 0;
                        val = (int32_t)(BIT_AT(I1(_opcode), 10));
                        val = (int32_t)((val<<3) | BIT_RANGE(I2(_opcode), 12, 14));
                        val = (int32_t)((val<<8) | BIT_RANGE(I2(_opcode), 0, 7));
                        return ThumbExpandImm_C(val,0).first;
                    }else{
                        reterror("unimplemented");
                    }
                    
                case lsl:
                    if (subtype() == st_immediate) {
                        int32_t val = 0;
                        val = (int32_t)(BIT_RANGE(I2(_opcode), 12, 14));
                        val = (int32_t)((val<<2) | BIT_RANGE(I2(_opcode), 6, 7));
                        return DecodeImmShift(0b00, val).second;
                    }else{
                        reterror("unimplemented");
                    }
                    
                case add:
                    retassure(subtype() == st_immediate, "bad subtype");
                    return (BIT_AT(I1(_opcode), 10) << 11) | (BIT_RANGE(I2(_opcode), 12, 14)<<8) | BIT_RANGE(I2(_opcode), 0, 7);
                    
                default:
                    reterror("failed to get imm value for insn size=4");
                    break;
            }
        }
        break;

        default:
            reterror("imm: got bad insnsize");
            break;
    }
    return 0;
}

uint8_t thumb::rd(){
    switch (insnsize()) {
        case 2:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rd value of unknown instruction");
                    break;
                case mov:
                    if (subtype() == st_register) {
                        return BIT_RANGE(_opcode, 0, 2);
                    }else{
                        return BIT_RANGE(_opcode, 8, 10);
                    }
                case add:
                    if (subtype() == st_register) {
                        return BIT_RANGE(_opcode, 0, 2);
                    }else if (subtype() == st_immediate){
                        if (BIT_RANGE(_opcode, 9, 15) == 0b0001110){
                            //T1 encoding
                            return BIT_RANGE(_opcode, 0, 2);
                        }else{
                            retassure(BIT_RANGE(_opcode, 11, 15) == 0b00110, "Bad encoding");
                            //T2 encoding
                            return BIT_RANGE(_opcode, 8, 10);
                        }
                    }else if (BIT_RANGE(_opcode, 11,15) == 0b10101){
                        //T1 SP plus immediate
                        return BIT_RANGE(_opcode, 8, 10);
                    }else if (BIT_RANGE(_opcode, 7,15) == 0b101100000){
                        //T2 SP plus immediate
                        return 13;
                    }else{
                        reterror("unexpected subtype");
                    }
                case lsl:
                    if (subtype() == st_immediate) {
                        return BIT_RANGE(_opcode, 0, 2);
                    }else{
                        reterror("unimplemented");
                    }
                    
                default:
                    reterror("failed to get rd value for insn size=2");
                    break;
            }
        }
        break;

        case 4:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rd value of unknown instruction");
                    break;

                case add:
                    return BIT_RANGE(I2(_opcode), 8, 11);
                    break;
                    
                case mov:
                case orr:
                case lsl:
                    if (subtype() == st_immediate) {
                        return BIT_RANGE(I2(_opcode), 8, 11);
                    }else{
                        reterror("unimplemented");
                    }
                case movt:
                    return BIT_RANGE(I2(_opcode), 8, 11);
                    
                default:
                    reterror("failed to get rd value for insn size=4");
                    break;
            }
        }
        break;

        default:
            reterror("rd: got bad insnsize");
            break;
    }
    return 0;
}

uint8_t thumb::rn(){
    switch (insnsize()) {
        case 2:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rn value of unknown instruction");
                    break;
                    
                case cmp:
                    return BIT_RANGE(_opcode, 0, 10);
                    
                case cbz:
                case cbnz:
                    return BIT_RANGE(_opcode, 0, 2);

                case str:
                case ldr:
                    if (BIT_RANGE(_opcode, 12, 15) == 0b1001) return 13;
                    retassure(BIT_RANGE(_opcode, 12, 15) == 0b0110, "Bad encoding");
                    return BIT_RANGE(_opcode, 3, 5);
                    
                case add:
                    if (BIT_RANGE(_opcode, 9, 15) == 0b0001110){
                        //T1 encoding
                        return BIT_RANGE(_opcode, 3, 5);
                    }else if (BIT_RANGE(_opcode, 11,15) == 0b10101){
                        //T1 SP plus immediate
                        return 13;
                    }else if (BIT_RANGE(_opcode, 7,15) == 0b101100000){
                        //T2 SP plus immediate
                        return 13;
                    }else if (BIT_RANGE(_opcode, 11, 15) == 0b00110){
                        //T2 encoding immediate
                        return BIT_RANGE(_opcode, 8, 10);
                    }else if (BIT_RANGE(_opcode, 8, 15) == 0b01000100){
                        //T2 encoding register
                        return BIT_RANGE(_opcode, 0, 2);
                    }else{
                        reterror("Bad encoding");
                    }
                
                default:
                    reterror("failed to get rn value for insn size=2");
                    break;
            }
        }
        break;

        case 4:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rn value of unknown instruction");
                    break;
                    
                case cmp:
                case tst:
                case orr:
                    return BIT_RANGE(I1(_opcode), 0, 3);

                case ldr:
                    if (subtype() == st_immediate){
                        return BIT_RANGE(I1(_opcode), 0, 3);
                    }else{
                        reterror("unimplemented");
                    }
                    
                case add:
                    if (subtype() == st_register) {
                        return BIT_RANGE(I1(_opcode), 0, 3);
                    }else if (subtype() == st_immediate){
                        if (BIT_RANGE(I1(_opcode) | SET_BITS(0b11, 9), 5,15) == 0b11110111000){
                            //T3 & T4
                            return BIT_RANGE(I1(_opcode), 0, 3);
                        }else{
                            reterror("invalid encoding");
                        }
                    }else{
                        reterror("TODO");
                    }

                default:
                    reterror("failed to get rn value for insn size=4");
                    break;
            }
        }
        break;

        default:
            reterror("rn: got bad insnsize");
            break;
    }
    return 0;
}

uint8_t thumb::rm(){
    switch (insnsize()) {
        case 2:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rm value of unknown instruction");
                    break;
                case mov:
                    if (subtype() == st_register) {
                        return BIT_RANGE(_opcode, 3, 6);
                    }else{
                        reterror("unimplemented");
                    }
                case add:
                    if (subtype() == st_register) {
                        if (BIT_RANGE(_opcode, 9, 15) == 0b0001100) {
                            //T1 encoding
                            return BIT_RANGE(_opcode, 6, 8);
                        }else{
                            //T2 encoding
                            return BIT_RANGE(_opcode, 3, 6);
                        }
                    }else{
                        reterror("unimplemented");
                    }
                case bx:
                    return BIT_RANGE(_opcode, 3, 6);
                    
                case lsl:
                    if (subtype() == st_immediate) {
                        return BIT_RANGE(_opcode, 3, 5);
                    }else{
                        reterror("unimplemented");
                    }
                    
                default:
                    reterror("failed to get rm value for insn size=2");
                    break;
            }
        }
        break;

        case 4:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rm value of unknown instruction");
                    break;
                    
                case add:
                    if (subtype() == st_register) {
                        return BIT_RANGE(I2(_opcode), 0, 3);
                    }else{
                        reterror("unimplemented");
                    }
                    break;
                    
                case lsl:
                    if (subtype() == st_immediate) {
                        return BIT_RANGE(I2(_opcode), 0, 3);
                    }else{
                        reterror("unimplemented");
                    }
                    break;
                    
                default:
                    reterror("failed to get rm value for insn size=4");
                    break;
            }
        }
        break;

        default:
            reterror("rm: got bad insnsize");
            break;
    }
    return 0;
}

enum cond thumb::condition(){
    switch (insnsize()) {
        case 2:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rt value of unknown instruction");
                    break;

                default:
                    reterror("failed to get rt value for insn size=2");
                    break;
            }
        }
        break;

        case 4:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rt value of unknown instruction");
                    break;

                case bcond:
                    if (supertype() == sut_branch_imm) {
                        retassure(BIT_RANGE(I1(_opcode), 11, 15) == 0b11110 && BIT_AT(I2(_opcode), 12) == 0, "branch is unconditional");
                        return (enum cond)BIT_RANGE(I1(_opcode), 6, 9);
                    }else{
                        reterror("unimplemented");
                    }
                    break;
                    
                default:
                    reterror("failed to get rt value for insn size=4");
                    break;
            }
        }
        break;

        default:
            reterror("rt: got bad insnsize");
            break;
    }
}

uint8_t thumb::rt(){
    switch (insnsize()) {
        case 2:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rt value of unknown instruction");
                    break;
                case ldr:
                case str:
                    if (subtype() == st_literal) {
                        return BIT_RANGE(_opcode, 8, 10);
                    }else if (subtype() == st_immediate) {
                        if (BIT_RANGE(_opcode, 11, 15) == 0b01101 /* T1 */) {
                            return BIT_RANGE(_opcode, 0, 2);
                        } else if (BIT_RANGE(_opcode, 12, 15) == 0b1001 /* T2 */) {
                            return BIT_RANGE(_opcode, 8, 10);
                        } else {
                            reterror("Bad encoding");
                        }
                    }else{
                        reterror("unimplemented");
                    }
                    
                default:
                    reterror("failed to get rt value for insn size=2");
                    break;
            }
        }
        break;

        case 4:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get rt value of unknown instruction");
                    break;

                case ldr:
                    if (subtype() == st_literal) {
                        return BIT_RANGE(I2(_opcode), 12, 15);
                    }else if (subtype() == st_immediate) {
                        return BIT_RANGE(I2(_opcode), 12, 15);
                    }else{
                        reterror("unimplemented");
                    }
                    break;
                    
                default:
                    reterror("failed to get rt value for insn size=4");
                    break;
            }
        }
        break;

        default:
            reterror("rt: got bad insnsize");
            break;
    }
}

register_list thumb::reglist(){
    switch (insnsize()) {
        case 2:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get reglist value of unknown instruction");
                    break;
                case push:
                {
                    uint16_t ret = (uint16_t)BIT_RANGE(_opcode, 0, 7);
                    register_list *r = (register_list *)&ret;
                    r->lr = BIT_AT(_opcode, 8);
                    return *r;
                }
                case pop:
                {
                    uint16_t ret = (uint16_t)BIT_RANGE(_opcode, 0, 7);
                    register_list *r = (register_list *)&ret;
                    r->pc = BIT_AT(_opcode, 8);
                    return *r;
                }

                default:
                    reterror("failed to get reglist value for insn size=2");
                    break;
            }
        }
        break;

        case 4:
        {
            switch (type()) {
                case unknown:
                    reterror("can't get reglist value of unknown instruction");
                    break;
                
                case push:
                case pop:
                    {
                        uint16_t ret = (uint16_t)((BIT_AT(I2(_opcode), 14) << 13) | BIT_RANGE(I2(_opcode), 0, 12));
                        register_list *r = (register_list *)&ret;
                        return *r;
                    }
                    
                default:
                    reterror("failed to get reglist value for insn size=4");
                    break;
            }
        }
        break;

        default:
            reterror("imm: got bad insnsize");
            break;
    }
}


//int32_t insn32_thumb::rdn(){
//    switch (insnsize()) {
//        case 2:
//        {
//            switch (type()) {
//                case unknown:
//                    reterror("can't get rdn value of unknown instruction");
//                    break;
//                case and_:
//                    return BIT_RANGE(_opcode, 0,2); //T1 encoding
//                default:
//                    reterror("failed to get rdn value for insn size=2");
//                    break;
//            }
//        }
//        break;
//
//        case 4:
//        {
//            switch (type()) {
//                case unknown:
//                    reterror("can't get rdn value of unknown instruction");
//                    break;
//                default:
//                    reterror("failed to get rdn value for insn size=4");
//                    break;
//            }
//        }
//        break;
//
//        default:
//            reterrot("rdn: got bad insnsize");
//            break;
//    }
//    return 0;
//}

//int32_t insn32_thumb::rm(){
//    switch (insnsize()) {
//        case 2:
//        {
//            switch (type()) {
//                case unknown:
//                    reterror("can't get rm value of unknown instruction");
//                    break;
//                case and_:
//                    return BIT_RANGE(_opcode, 3,5); //T1 encoding
//                default:
//                    reterror("failed to get rm value for insn size=2");
//                    break;
//            }
//        }
//        break;
//
//        case 4:
//        {
//            switch (type()) {
//                case unknown:
//                    reterror("can't get rm value of unknown instruction");
//                    break;
//                default:
//                    reterror("failed to get rm value for insn size=4");
//                    break;
//            }
//        }
//        break;
//
//        default:
//            reterrot("rm: got bad insnsize");
//            break;
//    }
//    return 0;
//}

#pragma mark cast operators
thumb::operator enum type(){
    return type();
}

thumb::operator loc_t(){
    return (loc_t)_pc;
}
