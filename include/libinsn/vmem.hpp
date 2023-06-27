//
//  vmem.hpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#ifndef vmem_hpp
#define vmem_hpp

#include <libinsn/insn.hpp>

#include <iostream>
#include <memory>
#include <stdint.h>
#include <map>

namespace tihmstar{
    namespace libinsn{
    enum vmprot{
        kVMPROTALL   = 0,
        kVMPROTREAD  = 1 << 0,
        kVMPROTWRITE = 1 << 1,
        kVMPROTEXEC  = 1 << 2,
    };
    struct vsegment{
        const uint8_t *buf;
        size_t size;
        uint64_t vaddr;
        vmprot perms;
        std::string segname;
    };
    template <class insn>
        class vmem{
            struct pvsegment{
                const uint8_t *buf;
                size_t size;
                uint64_t vaddr;
                vmprot perms;
                char segname[0];
            };

            uint32_t _segNum;
            uint64_t _offset;
            uint32_t _segmentsCnt;
            std::shared_ptr<pvsegment*> _segments;
            std::shared_ptr<uint8_t>    _segmentsStorage;

            std::map<int,std::shared_ptr<vmem>> _submaps;
            
            bool isInSegRange(const pvsegment *seg, typename insn::loc_t pos) const noexcept;
            const pvsegment *curSeg() const;
            const pvsegment *segmentForLoc(typename insn::loc_t loc) const;
            typename insn::loc_t memmemInSeg(const pvsegment *seg, const void *little, size_t little_len, typename insn::loc_t startLoc = 0) const;

            uint8_t insnSize() const;
            void initSubmaps();
        public:
            ~vmem();
            vmem(const std::vector<vsegment> &segments);
            vmem(const vmem& copy, typename insn::loc_t pos = 0, int perm = kVMPROTALL);
            vmem(const vmem *copy, typename insn::loc_t pos = 0, int perm = kVMPROTALL);
            vmem &operator=(const vmem &m);

            template <class src_insn>
            vmem(const vmem<src_insn>& copy, typename insn::loc_t pos = 0, int perm = kVMPROTALL);
            template <class src_insn>
            vmem(const vmem<src_insn> *copy, typename insn::loc_t pos = 0, int perm = kVMPROTALL);
            template <class src_insn>
            vmem &operator=(const vmem<src_insn> &m);
            
            vmem getIter(typename insn::loc_t pos = 0, int perm = kVMPROTEXEC) const;
            
            vmem seg(typename insn::loc_t pos) const;
            
            typename insn::loc_t deref(typename insn::loc_t pos) const;
            typename insn::loc_t memmem(const void *little, size_t little_len, typename insn::loc_t startLoc = 0) const;
            typename insn::loc_t memstr(const char *little) const;
            bool isInRange(typename insn::loc_t pos) const noexcept;

            /*--segment functions but for vmem--*/
            void nextSeg();
            void prevSeg();
            size_t curSegSize();
            
            //iterator operator
            insn operator+(int i);
            insn operator-(int i);
            insn operator++();
            insn operator--();
            vmem &operator+=(int i);
            vmem &operator-=(int i);
            vmem &operator=(typename insn::loc_t p);

            //segment info functions
            int curPerm() const;
            const void *memoryForLoc(typename insn::loc_t loc) const;
            
            //deref operator
            typename insn::loc_t pc() const;
            uint32_t value(typename insn::loc_t p) const; //arbitrary pos
            uint64_t doublevalue(typename insn::loc_t p) const; //arbitrary pos
            uint32_t value() const; //curpos
            uint64_t doublevalue() const; //curpos
            
            //insn operator
            insn getinsn() const;
            insn operator()();
            operator typename insn::loc_t() const;
            
            friend class vmem<arm64::insn>;
            friend class vmem<arm32::arm>;
            friend class vmem<arm32::thumb>;
        };
    };
};
#endif /* vmem_hpp */
