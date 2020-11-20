//
//  insn32.cpp
//  libinsn
//
//  Created by tihmstar on 09.10.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//


#include <libgeneral/macros.h>

#include "insn32_thumb.hpp"
#include "INSNexception.hpp"


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

insn32_thumb::insn32_thumb(uint32_t opcode, uint32_t pc)
: _opcode(opcode), _pc(pc), _type(unknown), _subtype(st_general), _supertype(sut_general)
{
    //
}

insn32_thumb::~insn32_thumb(){
    //
}

struct regtypes{
    enum insn32::type type;
    enum insn32::subtype subtype;
    enum insn32::supertype supertype;
};

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
            _stage2_insn[0b0000] = {insn32::and_,insn32::st_register};
            _stage2_insn[0b0001] = {insn32::eor,insn32::st_register};
            _stage2_insn[0b0010] = {insn32::lsl,insn32::st_register};
            _stage2_insn[0b0011] = {insn32::lsr,insn32::st_register};
            _stage2_insn[0b0100] = {insn32::asr,insn32::st_register};
            _stage2_insn[0b0101] = {insn32::adc,insn32::st_register};
            _stage2_insn[0b0110] = {insn32::sbc,insn32::st_register};
            _stage2_insn[0b0111] = {insn32::ror,insn32::st_register};
            _stage2_insn[0b1000] = {insn32::tst,insn32::st_register};
            _stage2_insn[0b1001] = {insn32::rsb,insn32::st_immediate};
            _stage2_insn[0b1010] = {insn32::cmp,insn32::st_register};
            _stage2_insn[0b1011] = {insn32::cmn,insn32::st_register};
            _stage2_insn[0b1100] = {insn32::orr,insn32::st_register};
            _stage2_insn[0b1101] = {insn32::mul,insn32::st_general};
            _stage2_insn[0b1110] = {insn32::bic,insn32::st_register};
            _stage2_insn[0b1111] = {insn32::mvn,insn32::st_register};
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
            for (int i=0; i<0b100; i++) _stage2_insn[0b0000 | SET_BITS(i,0)] = {insn32::add,insn32::st_register};

            _stage2_insn[0b0100] = {insn32::unknown};//0100 UNPREDICTABLE

            _stage2_insn[0b0101] = {insn32::cmp,insn32::st_register};
            for (int i=0; i<0b10; i++) _stage2_insn[0b0110 | SET_BITS(i,0)] = {insn32::cmp,insn32::st_register};

            for (int i=0; i<0b100; i++) _stage2_insn[0b1000 | SET_BITS(i,0)] = {insn32::mov,insn32::st_register};

            for (int i=0; i<0b10; i++) _stage2_insn[0b1100 | SET_BITS(i,0)] = {insn32::bx,insn32::st_register};
            for (int i=0; i<0b10; i++) _stage2_insn[0b1110 | SET_BITS(i,0)] = {insn32::blx,insn32::st_register};
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
            _stage2_insn[0b0110011] = {insn32::cps};

            for (int i=0; i<0b100; i++) _stage2_insn[0b0000000 | SET_BITS(i,0)] = {insn32::add}; //not general add
            for (int i=0; i<0b100; i++) _stage2_insn[0b0000100 | SET_BITS(i,0)] = {insn32::sub}; //not general sub

            for (int i=0; i<0b1000; i++) _stage2_insn[0b0001000 | SET_BITS(i,0)] = {insn32::cbz};

            for (int i=0; i<0b10; i++) _stage2_insn[0b0010000 | SET_BITS(i,0)] = {insn32::sxth};
            for (int i=0; i<0b10; i++) _stage2_insn[0b0010010 | SET_BITS(i,0)] = {insn32::sxtb};

            for (int i=0; i<0b10; i++) _stage2_insn[0b0010100 | SET_BITS(i,0)] = {insn32::uxth};
            for (int i=0; i<0b10; i++) _stage2_insn[0b0010110 | SET_BITS(i,0)] = {insn32::uxtb};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b0011000 | SET_BITS(i,0)] = {insn32::cbz};

            for (int i=0; i<0b10000; i++) _stage2_insn[0b0100000 | SET_BITS(i,0)] = {insn32::push,insn32::st_general,insn32::sut_memory};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b1001000 | SET_BITS(i,0)] = {insn32::cbnz};

            for (int i=0; i<0b10; i++) _stage2_insn[0b1010000 | SET_BITS(i,0)] = {insn32::rev};
            for (int i=0; i<0b10; i++) _stage2_insn[0b1010010 | SET_BITS(i,0)] = {insn32::rev16};
            for (int i=0; i<0b10; i++) _stage2_insn[0b1010110 | SET_BITS(i,0)] = {insn32::revsh};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b1011000 | SET_BITS(i,0)] = {insn32::cbnz};

            for (int i=0; i<0b10000; i++) _stage2_insn[0b1100000 | SET_BITS(i,0)] = {insn32::pop,insn32::st_general,insn32::sut_memory};

            for (int i=0; i<0b1000; i++) _stage2_insn[0b1110000 | SET_BITS(i,0)] = {insn32::bkpt};

            /* ----- THESE MORE DECODING IN A FURTHER STEP ----- */
            for (int i=0; i<0b1000; i++) _stage2_insn[0b1111000 | SET_BITS(i,0)] = {insn32::unknown}; //If-Then, and hints
            
        }
        constexpr regtypes operator[](uint8_t i) const{
            return _stage2_insn[i];
        }
    };

    constexpr const decoder_stage2 decode_table_stage2;

    auto predec = decode_table_stage2[BIT_RANGE(i,5,11)];
    if (predec.type == insn32::unknown) {
        //If-Then, and hints
        
        if (BIT_RANGE(i, 8, 15) != 0b10111111) return {insn32::unknown}; //something went wrong here :/
        
        if (BIT_RANGE(i, 0, 3) != 0b0000) return {insn32::it};
            
        switch (BIT_RANGE(i, 4, 7)) {
            case 0b0000:
                return {insn32::nop};
            case 0b0001:
                return {insn32::yield};
            case 0b0010:
                return {insn32::wfe};
            case 0b0011:
                return {insn32::wfi};
            case 0b0100:
                return {insn32::sev};

            default:
                return {insn32::unknown}; //something went wrong here :/
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
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b00000 << 1) | SET_BITS(i,0)] = {true, {insn32::lsl,insn32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b00100 << 1) | SET_BITS(i,0)] = {true, {insn32::lsr,insn32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b01000 << 1) | SET_BITS(i,0)] = {true, {insn32::asr,insn32::st_immediate}};

            for (int i=0; i<2; i++) _stage1_insn[(0b01100 << 1) | SET_BITS(i,0)] = {true, {insn32::add,insn32::st_register}};
            for (int i=0; i<2; i++) _stage1_insn[(0b01101 << 1) | SET_BITS(i,0)] = {true, {insn32::sub,insn32::st_register}};

            for (int i=0; i<2; i++) _stage1_insn[(0b01110 << 1) | SET_BITS(i,0)] = {true, {insn32::add,insn32::st_immediate}};
            for (int i=0; i<2; i++) _stage1_insn[(0b01111 << 1) | SET_BITS(i,0)] = {true, {insn32::sub,insn32::st_immediate}};

            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b10000 << 1) | SET_BITS(i,0)] = {true, {insn32::mov,insn32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b10100 << 1) | SET_BITS(i,0)] = {true, {insn32::cmp,insn32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b11000 << 1) | SET_BITS(i,0)] = {true, {insn32::add,insn32::st_immediate}};
            for (int i=0; i<((0b100)<<1); i++) _stage1_insn[(0b11100 << 1) | SET_BITS(i,0)] = {true, {insn32::sub,insn32::st_immediate}};
        }

        //Data processing on page A5-7
        {
            for (int i=0; i<4; i++) _stage1_insn[(0b010000 << 2) | SET_BITS(i,0)] = {false, .next_stage_decoder = data_processing_decoder16};
        }
        
        //Special data instructions and branch and exchange on page A5-8
        {
            for (int i=0; i<4; i++) _stage1_insn[(0b010001 << 2) | SET_BITS(i,0)] = {false, .next_stage_decoder = special_instructions_decoder16};
        }
        
        //Load from Literal Pool, see LDR (literal) on page A6-90
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b010010 << 2) | SET_BITS(i,0)] = {true, {insn32::ldr, insn32::st_literal, insn32::sut_memory}};
        }
        
        //Load/store single data item on page A5-9
        {
            for (int i=0; i<2; i++) _stage1_insn[(0b0101000 << 1) | SET_BITS(i,0)] = {true, {insn32::str,insn32::st_register, insn32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101001 << 1) | SET_BITS(i,0)] = {true, {insn32::strh,insn32::st_register, insn32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101010 << 1) | SET_BITS(i,0)] = {true, {insn32::strb,insn32::st_register, insn32::sut_memory}};

            for (int i=0; i<2; i++) _stage1_insn[(0b0101011 << 1) | SET_BITS(i,0)] = {true, {insn32::ldrsb,insn32::st_register, insn32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101100 << 1) | SET_BITS(i,0)] = {true, {insn32::ldr,insn32::st_register, insn32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101101 << 1) | SET_BITS(i,0)] = {true, {insn32::ldrh,insn32::st_register, insn32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101110 << 1) | SET_BITS(i,0)] = {true, {insn32::ldrb,insn32::st_register, insn32::sut_memory}};
            for (int i=0; i<2; i++) _stage1_insn[(0b0101111 << 1) | SET_BITS(i,0)] = {true, {insn32::ldrsh,insn32::st_register, insn32::sut_memory}};


            for (int i=0; i<0b1000; i++) _stage1_insn[(0b01100 << 3) | SET_BITS(i,0)] = {true, {insn32::str,insn32::st_immediate, insn32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b01101 << 3) | SET_BITS(i,0)] = {true, {insn32::ldr,insn32::st_immediate, insn32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b01110 << 3) | SET_BITS(i,0)] = {true, {insn32::strb,insn32::st_immediate, insn32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b01111 << 3) | SET_BITS(i,0)] = {true, {insn32::ldrb,insn32::st_immediate, insn32::sut_memory}};

            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10000 << 3) | SET_BITS(i,0)] = {true, {insn32::strh,insn32::st_immediate, insn32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10001 << 3) | SET_BITS(i,0)] = {true, {insn32::ldrh,insn32::st_immediate, insn32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10010 << 3) | SET_BITS(i,0)] = {true, {insn32::str,insn32::st_immediate, insn32::sut_memory}};
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10011 << 3) | SET_BITS(i,0)] = {true, {insn32::ldr,insn32::st_immediate, insn32::sut_memory}};
        }
        
        //Generate PC-relative address, see ADR on page A6-30
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b10100 << 3) | SET_BITS(i,0)] = {true, {insn32::adr,insn32::st_general}};
        }
        
        //Generate SP-relative address, see ADD (SP plus immediate) on page A6-26
        {
            for (int i=0; i<0b10101; i++) _stage1_insn[(0b10100 << 3) | SET_BITS(i,0)] = {true, {insn32::add,insn32::st_general}};//not a general add here
        }
        
        //Miscellaneous 16-bit instructions on page A5-10
        {
            for (int i=0; i<0b10000; i++) _stage1_insn[(0b101100 << 2) | SET_BITS(i,0)] = {false, .next_stage_decoder = miscellaneous_decoder16};

        }
        
        //Store multiple registers, see STM / STMIA / STMEA on page A6-218
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b110000 << 2) | SET_BITS(i,0)] = {true, {insn32::stm,insn32::st_general, insn32::sut_memory}};
        }
        
        //Load multiple registers, see LDM / LDMIA / LDMFD on page A6-84
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b110010 << 2) | SET_BITS(i,0)] = {true, {insn32::ldm,insn32::st_general, insn32::sut_memory}};
        }
        
        //Conditional branch, and supervisor call
        {
            for (int i=0; i<0b1110; i++) _stage1_insn[0b11010000 | SET_BITS(i,0)] = {true, {insn32::b,insn32::st_general, insn32::sut_branch_imm}};

            _stage1_insn[0b11011110] = {true, {insn32::unknown}}; //Permanently UNDEFINED
            
            _stage1_insn[0b11011111] = {true, {insn32::svc}};
        }
        
        //Unconditional Branch, see B on page A6-40
        {
            for (int i=0; i<0b1000; i++) _stage1_insn[(0b111000 << 2) | SET_BITS(i,0)] = {true, {insn32::b,insn32::st_general, insn32::sut_branch_imm}};
        }
    };
    constexpr decoder_val operator[](uint32_t i) const{
        return _stage1_insn[BIT_RANGE(i, 8, 15)];
    }
};

#pragma mark second stage decoders thumb32


#pragma mark decoding unit thumb16

struct decoder_stage1_thumb32{
#define I1(i) (i >> 16)
#define I2(i) (i & 0xffff)
    decoder_val _stage1_insn[(1<<9) - 0b010000000]; //9 bit but no values lower than b010000000
    constexpr decoder_stage1_thumb32() : _stage1_insn{}
    {
        //Load/store multiple on page A5-20
        {
            _stage1_insn[(0b010001000) - 0b010000000] = {true, {insn32::stm,insn32::st_general, insn32::sut_memory}};
            
            //possibly POP
            _stage1_insn[(0b010001011) - 0b010000000] = {true, {insn32::ldm,insn32::st_general, insn32::sut_memory}};
            
            //possibly PUSH
            _stage1_insn[(0b010010010) - 0b010000000] = {true, {insn32::stmdb,insn32::st_general, insn32::sut_memory}};

            _stage1_insn[(0b010010000) - 0b010000000] = {true, {insn32::stmdb,insn32::st_general, insn32::sut_memory}};
        }
        
        //Load/store dual or exclusive, table branch on page A5-21
        {
            _stage1_insn[(0b010000100) - 0b010000000] = {true, {insn32::strex,insn32::st_register_extended, insn32::sut_memory}};
            _stage1_insn[(0b010000101) - 0b010000000] = {true, {insn32::ldrex,insn32::st_register_extended, insn32::sut_memory}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010000110 | SET_BITS(i, 3)) - 0b010000000] = {true, {insn32::strd,insn32::st_general, insn32::sut_memory}};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b010010100 | SET_BITS(i, 3) | SET_BITS(j, 1)) - 0b010000000] = {true, {insn32::strd,insn32::st_general, insn32::sut_memory}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010000111 | SET_BITS(i, 3)) - 0b010000000] = {true, {insn32::ldrd,insn32::st_general, insn32::sut_memory}};
            for (int i=0; i<0b10; i++) for (int j=0; j<0b10; j++) _stage1_insn[(0b010010101 | SET_BITS(i, 3) | SET_BITS(j, 1)) - 0b010000000] = {true, {insn32::ldrd,insn32::st_general, insn32::sut_memory}};
            
            //possibly STREXH or undefined
            _stage1_insn[(0b010001100) - 0b010000000] = {true, {insn32::strexb,insn32::st_register_extended, insn32::sut_memory}};

            //possibly TTH or LDREXB or LDREXH or undefined
            _stage1_insn[(0b010001101) - 0b010000000] = {true, {insn32::ttb}};
        }
        
        //Data processing (shifted register) on page A5-26
        {
            //possibly TST or undefined
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010100000 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::and_,insn32::st_register}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010100010 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::bic,insn32::st_register}};

            //possibly (Move register and immediate shifts)
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010100100 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::orr,insn32::st_register}};

            //possibly MVN
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010100110 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::orn,insn32::st_register}};

            //possibly TEQ or undefined
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010101000 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::eor,insn32::st_register}};

            //possibly TEQ or undefined
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010110000 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::add,insn32::st_register}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010110100 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::adc,insn32::st_register}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010110110 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::sbc,insn32::st_register}};

            //possibly CMP or undefined
            for (int i=0; i<0b10; i++) _stage1_insn[(0b010111010 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::sub,insn32::st_register}};

            for (int i=0; i<0b10; i++) _stage1_insn[(0b010111100 | SET_BITS(i, 0)) - 0b010000000] = {true, {insn32::rsb,insn32::st_register}};
        }
        
        //Coprocessor instructions on page A5-32
        {
            
        }
#warning TODO
    };
    constexpr decoder_val operator[](uint32_t i) const{
        auto predec = _stage1_insn[BIT_RANGE(I1(i), 5, 12)];
        
        switch (predec.types.type) {
            case insn32::ldm:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1101) {
                    return {true, {insn32::pop}};
                }
                break;
            case insn32::stmdb:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1101) {
                    return {true, {insn32::push}};
                }
                break;
            case insn32::strexb:
                if (BIT_RANGE(I2(i), 4, 7) == 0b0101) {
                    return {true, {insn32::strexh,insn32::st_register_extended, insn32::sut_memory}};
                }else if (BIT_RANGE(I2(i), 4, 7) != 0b0100){
                    return {true, {insn32::unknown}};
                }
            case insn32::ttb:
                if (BIT_RANGE(I2(i), 4, 7) == 0b0101) {
                    return {true, {insn32::tth}};
                }else if (BIT_RANGE(I2(i), 4, 7) == 0b0100){
                    return {true, {insn32::ldrexb}};
                }else if (BIT_RANGE(I2(i), 4, 7) == 0b0101){
                    return {true, {insn32::ldrexh}};
                }else if (BIT_RANGE(I2(i), 4, 7) != 0b0100){
                    return {true, {insn32::unknown}};
                }
            case insn32::and_:
                if (BIT_RANGE(I2(i), 8, 11) == 0b1111) {
                    if (BIT_AT(I1(i), 4) == 1) {
                        return {true, {insn32::tst}};
                    }else{
                        return {true, {insn32::unknown}};
                    }
                }
            case insn32::orr:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    //(Move register and immediate shifts)
                    switch (BIT_RANGE(I2(i), 4, 5)) {
                        case 0b00:
                            if (BIT_RANGE(I2(i), 12, 14) | BIT_RANGE(I2(i), 6, 7)) {
                                return {true, {insn32::lsl,insn32::st_immediate}};
                            }else{
                                return {true, {insn32::mov,insn32::st_register}};
                            }
                        case 0b01:
                            return {true, {insn32::lsr,insn32::st_immediate}};
                        case 0b10:
                            return {true, {insn32::asr,insn32::st_immediate}};
                        case 0b11:
                            if (BIT_RANGE(I2(i), 12, 14) | BIT_RANGE(I2(i), 6, 7)) {
                                return {true, {insn32::ror,insn32::st_immediate}};
                            }else{
                                return {true, {insn32::rrx}};
                            }
                    }
                }
            case insn32::orn:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    return {true, {insn32::mvn, insn32::st_register}};
                }
                break;
            case insn32::eor:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    if (BIT_AT(I1(i), 4) == 1) {
                        return {true, {insn32::teq, insn32::st_register}};
                    }else{
                        return {true, {insn32::unknown}};
                    }
                }
            case insn32::add:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    if (BIT_AT(I1(i), 4) == 1) {
                        return {true, {insn32::cmn, insn32::st_register}};
                    }else{
                        return {true, {insn32::unknown}};
                    }
                }
            case insn32::sub:
                if (BIT_RANGE(I1(i), 0, 3) == 0b1111) {
                    if (BIT_AT(I1(i), 4) == 1) {
                        return {true, {insn32::cmp, insn32::st_register}};
                    }else{
                        return {true, {insn32::unknown}};
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

uint32_t insn32_thumb::opcode(){
    return _opcode;
}

uint32_t insn32_thumb::pc(){
    return _pc;
}

enum insn32::cputype insn32_thumb::cputype(){
    return insn32::cputype::cpu_thumb;
}

uint8_t insn32_thumb::insnsize(){
    return (BIT_RANGE(_opcode, 11, 15) > 0b11100) ? 4 : 2;
}


enum insn32::type insn32_thumb::type(){
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
    }
    
    return _type;
}

enum insn32::subtype insn32_thumb::subtype(){
    return _subtype;
}

enum insn32::supertype insn32_thumb::supertype(){
    return _supertype;
}


//int32_t insn32_thumb::imm(){
//    switch (insnsize()) {
//        case 2:
//        {
//            switch (type()) {
//                case unknown:
//                    reterror("can't get imm value of unknown instruction");
//                    break;
//                case lsl:
//                case lsr:
//                case asr:
//                    return BIT_RANGE(_opcode, 6,10);
//                case add:
//                case sub:
//                {
//                    if (BIT_RANGE(_opcode, 13,15) == 0b000) {
//                        return BIT_RANGE(_opcode,6,8); //T1 encoding
//                    }else{
//                        return BIT_RANGE(_opcode,0,7); //T2 encoding
//                    }
//                }
//                case mov:
//                case cmp:
//                    return BIT_RANGE(_opcode,0,7); //T1 encoding
//                default:
//                    reterror("failed to get imm value for insn size=2");
//                    break;
//            }
//        }
//        break;
//        
//        case 4:
//        {
//            switch (type()) {
//                case unknown:
//                    reterror("can't get imm value of unknown instruction");
//                    break;
//                default:
//                    reterror("failed to get imm value for insn size=4");
//                    break;
//            }
//        }
//        break;
//        
//        default:
//            reterrot("imm: got bad insnsize");
//            break;
//    }
//    return 0;
//}

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
