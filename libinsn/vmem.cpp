//
//  vmem.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 28.09.19.
//  Copyright © 2019 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>
#include "../include/libinsn/INSNexception.hpp"
#include <string.h>
#include <algorithm>

#include "../include/libinsn/vmem.hpp"

#ifndef HAVE_MEMMEM
static void *memmem(const void *haystack_start, size_t haystack_len, const void *needle_start, size_t needle_len){
    const unsigned char *haystack = (const unsigned char *)haystack_start;
    const unsigned char *needle = (const unsigned char *)needle_start;
    const unsigned char *h = NULL;
    const unsigned char *n = NULL;
    size_t x = needle_len;
    
    /* The first occurrence of the empty string is deemed to occur at
     the beginning of the string.  */
    if (needle_len == 0) {
        return (void *)haystack_start;
    }
    
    /* Sanity check, otherwise the loop might search through the whole
     memory.  */
    if (haystack_len < needle_len) {
        return NULL;
    }
    
    for (; *haystack && haystack_len--; haystack++) {
        x = needle_len;
        n = needle;
        h = haystack;
        
        if (haystack_len < needle_len)
            break;
        
        if ((*haystack != *needle) || (*haystack + needle_len != *needle + needle_len))
            continue;
        
        for (; x; h++, n++) {
            x--;
            
            if (*h != *n)
                break;
            
            if (x == 0)
                return (void *)haystack;
        }
    }
    return NULL;
}
#endif

using namespace tihmstar;
using namespace tihmstar::libinsn;

template <class insn>
vmem<insn>::~vmem(){
    //
}

template <class insn>
vmem<insn>::vmem(const std::vector<vsegment> &segments_) :
_segNum(0),
_offset(0),
_segmentsCnt(0),
_segments(NULL),
_segmentsStorage(NULL)
{
    std::vector<vsegment> segments = segments_;
    std::sort(segments.begin(),segments.end(),[ ]( const vsegment& lhs, const vsegment& rhs){
        return lhs.vaddr < rhs.vaddr;
    });
    
    size_t segmentsStorageSize = 0;
    size_t segmentsCnt = 0;
    for (auto seg : segments) {
        size_t s = sizeof(pvsegment) + seg.segname.size() + 1;
        if (s & (sizeof(void*)-1)){
            s &= ~(sizeof(void*)-1);
            s+= sizeof(void*);
        }
        segmentsStorageSize += s;
        segmentsCnt++;
    }
    
    _segmentsStorage = {(uint8_t*)calloc(segmentsStorageSize,1),free};
    _segments = {(pvsegment**)calloc(segmentsCnt+1,sizeof(pvsegment*)),free};
    segmentsStorageSize = 0;
    for (auto seg : segments) {
        size_t s = sizeof(pvsegment) + seg.segname.size() + 1;
        if (s & (sizeof(void*)-1)){
            s &= ~(sizeof(void*)-1);
            s+= sizeof(void*);
        }
        pvsegment *cur = _segments.get()[_segmentsCnt++] = (pvsegment*)&_segmentsStorage.get()[segmentsStorageSize];
        cur->buf = seg.buf;
        cur->size = seg.size;
        cur->vaddr = seg.vaddr;
        cur->perms = seg.perms;
        strcpy(cur->segname, seg.segname.c_str());
        segmentsStorageSize += s;
    }
    initSubmaps();
}

#pragma mark vmem copy constructor
template <class insn>
vmem<insn>::vmem(const vmem<insn>& copy, typename insn::loc_t pos, int perm) :
_segNum(0),
_offset(0),
_segmentsCnt(copy._segmentsCnt),
_segments{},
_segmentsStorage(copy._segmentsStorage)
{
    if (!perm) {
        _segments = copy._segments;
        if (pos){
            *this = pos;
        }else{
            _segNum = copy._segNum;
            _offset = copy._offset;
        }
        _submaps = copy._submaps;
    }else{
        size_t segmentsCnt = 0;
        for (pvsegment **s = copy._segments.get(); *s; s++) segmentsCnt++;
        _segments = {(pvsegment**)calloc(segmentsCnt+1,sizeof(pvsegment*)),free};
        _segmentsCnt = 0;
        for (pvsegment **s = copy._segments.get(); *s; s++){
            if (s[0]->perms & perm){
                _segments.get()[_segmentsCnt++] = s[0];
            }
        }
        if (!pos){
            typename insn::loc_t oldpos = copy.pc();
            if (isInRange(oldpos)) pos = oldpos;
        }
        *this = pos;
    }
}

template <class insn>
vmem<insn>::vmem(const vmem<insn> *copy, typename insn::loc_t pos, int perm) :
_segNum(0),
_offset(0),
_segmentsCnt(copy->_segmentsCnt),
_segments{},
_segmentsStorage(copy->_segmentsStorage)
{
    if (!perm) {
        _segments = copy->_segments;
        _submaps = copy->_submaps;
    }else{
        size_t segmentsCnt = 0;
        for (pvsegment **s = copy->_segments.get(); *s; s++) segmentsCnt++;
        _segments = {(pvsegment**)calloc(segmentsCnt,sizeof(pvsegment*)),free};
        _segmentsCnt = 0;
        for (pvsegment **s = copy->_segments.get(); *s; s++){
            if (s[0]->perms & perm){
                _segments.get()[_segmentsCnt++] = s[0];
            }
        }
    }
    *this = pos;
}

template <class insn>
vmem<insn> &vmem<insn>::operator=(const vmem<insn> &m){
    _segNum = m._segNum;
    _offset = m._offset;
    _segmentsCnt = m._segmentsCnt;
    _segments = m._segments;
    _segmentsStorage = m._segmentsStorage;
    return *this;
}

#pragma mark vmem copy constructor from src_insn
template <class insn>
template <class src_insn>
vmem<insn>::vmem(const vmem<src_insn>& copy, typename insn::loc_t pos, int perm) :
_segNum(0),
_offset(0),
_segmentsCnt(0),
_segments{},
_segmentsStorage(copy._segmentsStorage)
{

    {
        size_t segmentsCnt = 0;
        for (auto **s = copy._segments.get(); *s; s++) segmentsCnt++;
        _segments = {(pvsegment**)calloc(segmentsCnt+1,sizeof(pvsegment*)),free};
        segmentsCnt = 0;
        for (auto **s = copy._segments.get(); *s; s++){
            if (s[0]->perms & perm){
                _segments.get()[_segmentsCnt++] = (pvsegment*)s[0];
            }
        }
    }
    *this = pos;
}

template <class insn>
template <class src_insn>
vmem<insn>::vmem(const vmem<src_insn> *copy, typename insn::loc_t pos, int perm) :
_segNum(0),
_offset(0),
_segmentsCnt(0),
_segments{},
_segmentsStorage(copy->_segmentsStorage)
{

    {
        size_t segmentsCnt = 0;
        for (auto **s = copy->_segments.get(); *s; s++) segmentsCnt++;
        _segments = {(pvsegment**)calloc(segmentsCnt+1,sizeof(pvsegment*)),free};
        segmentsCnt = 0;
        for (auto **s = copy->_segments.get(); *s; s++){
            if (s[0]->perms & perm){
                _segments.get()[_segmentsCnt++] = (pvsegment*)s[0];
            }
        }
    }
    *this = pos;
}

template <class insn>
template <class src_insn>
vmem<insn> &vmem<insn>::operator=(const vmem<src_insn> &m){
    _segNum = m._segNum;
    _offset = m._offset;
    {
        size_t segmentsCnt = 0;
        for (auto **s = m._segments.get(); *s; s++) segmentsCnt++;
        _segments = {(pvsegment**)calloc(segmentsCnt+1,sizeof(pvsegment*)),free};
        segmentsCnt = 0;
        for (auto **s = m._segments.get(); *s; s++){
            _segments.get()[_segmentsCnt++] = (pvsegment*)s[0];
        }
    }
    _segmentsStorage = m._segmentsStorage;
    return *this;
}

#pragma mark private

template <class insn>
bool vmem<insn>::isInSegRange(const pvsegment *seg, typename insn::loc_t pos) const noexcept{
    return (pos - seg->vaddr) < seg->size;
}

template <class insn>
const typename vmem<insn>::pvsegment *vmem<insn>::curSeg() const{
    return _segments.get()[_segNum];
}

template <class insn>
const typename vmem<insn>::pvsegment *vmem<insn>::segmentForLoc(typename insn::loc_t loc) const{
    for (pvsegment **s = _segments.get(); *s; s++) {
        pvsegment *seg = *s;
        if (isInSegRange(seg, loc)) {
            return seg;
        }
    }
    retcustomerror(out_of_range, "loc not within vmem");
}

template <class insn>
typename insn::loc_t vmem<insn>::memmemInSeg(const pvsegment *seg, const void *little, size_t little_len, typename insn::loc_t startLoc) const{
    typename insn::loc_t rt = 0;
    uint64_t startOffset = 0;
    if (startLoc) {
        startOffset = startLoc - seg->vaddr;
        assure(startOffset < seg->size);
    }
    if (uint64_t found = (uint64_t)::memmem(seg->buf+startOffset, seg->size-startOffset, little, little_len)) {
        rt = (typename insn::loc_t)(found - (uint64_t)seg->buf + seg->vaddr);
    }
    return rt;
}

template<>
uint8_t vmem<arm32::thumb>::insnSize() const{
    return getinsn().insnsize();
}

template <class insn>
inline uint8_t vmem<insn>::insnSize() const{
    return insn::size();
}

template <class insn>
inline void vmem<insn>::initSubmaps(){
    /*
     kVMPROTALL   = 0,
     kVMPROTREAD  = 1 << 0,
     kVMPROTWRITE = 1 << 1,
     kVMPROTEXEC  = 1 << 2,
     */
    for (int i=1; i<0b111; i++) {
        _submaps[i] = std::make_shared<vmem>(*this,0,i);
    }
}

#pragma mark vmem members


template <class insn>
vmem<insn> vmem<insn>::getIter(typename insn::loc_t pos, int perm) const{
    try {
        auto ret = *_submaps.at(perm);
        if (pos) ret = pos;
        return ret;
    } catch (tihmstar::exception &e) {
        throw;
    } catch (...){
        reterror("FATAL: getIter is unavailable on the current object!");
    }
}

template <class insn>
vmem<insn> vmem<insn>::seg(typename insn::loc_t pos) const{
    uint32_t segNum = 0;
    if (pos){
        for (pvsegment **s = _segments.get(); *s; s++,segNum++) {
            pvsegment *seg = *s;
            if (isInSegRange(seg, pos)) {
                goto found_segnum;
            }
        }
        retcustomerror(out_of_range, "loc not within vmem");
    found_segnum:;
    }

    vmem seg{*this};
    std::shared_ptr<pvsegment*> segments = {(pvsegment**)calloc(2,sizeof(pvsegment*)),free};
    pvsegment *segptr = segments.get()[0] = _segments.get()[segNum];
    seg._segments = segments;
    if (pos){
        seg._offset = pos - segptr->vaddr;
    }
    return seg;
}

template <class insn>
typename insn::loc_t vmem<insn>::deref(typename insn::loc_t pos) const{
    if constexpr(sizeof(typename insn::loc_t) == 4) {
        return value(pos);
    }else{
        return doublevalue(pos);
    }
}

template <class insn>
typename insn::loc_t vmem<insn>::memmem(const void *little, size_t little_len, typename insn::loc_t startLoc) const {
    for (pvsegment **s = _segments.get(); *s; s++) {
        pvsegment *seg = *s;
        if (startLoc && !isInSegRange(seg, startLoc)) continue;
        
        if (typename insn::loc_t rt = memmemInSeg(seg, little, little_len, startLoc)) {
            return rt;
        }
        startLoc = 0; //after one iteration, reset startLoc and search that segment (and all following) from beginning

    }
    retcustomerror(out_of_range,"memmem failed to find needle");
}

template <class insn>
typename insn::loc_t vmem<insn>::memstr(const char *little) const{
    return memmem(little, strlen(little));
}

template <class insn>
bool vmem<insn>::isInRange(typename insn::loc_t pos) const noexcept{
    for (pvsegment **s = _segments.get(); *s; s++) {
        pvsegment *seg = *s;
        if (isInSegRange(seg, pos)) {
            return true;
        }
    }
    return false;
}

template <class insn>
void vmem<insn>::nextSeg(){
    const pvsegment *nseg = _segments.get()[_segNum+1];
    retcustomassure(out_of_range, nseg, "overflow reached end of vmem");
    _segNum++;
    _offset = 0;
}

template <class insn>
void vmem<insn>::prevSeg(){
    retcustomassure(out_of_range, _segNum > 0, "overflow reached end of vmem");
    _segNum--;
    _offset = 0;
}

template <class insn>
size_t vmem<insn>::curSegSize(){
    return curSeg()->size;
}

#pragma mark iterator operator
template <class insn>
insn vmem<insn>::operator++(){
    size_t curSegSize = curSeg()->size;
    _offset+=insnSize();
    if (_offset + sizeof(uint32_t) >= curSegSize){
        //next seg
        const pvsegment *nseg = _segments.get()[_segNum+1];
        retcustomassure(out_of_range, nseg, "overflow reached end of vmem");
        _segNum++;
        _offset = 0;
    }
    return getinsn();
}

template <>
arm32::thumb vmem<arm32::thumb>::operator--(){
    uint8_t s = 2;
    if (_offset < s){
        //prev seg
        retcustomassure(out_of_range, _segNum>0, "underflow reached end of vmem");
        _segNum--;
        _offset = curSeg()->size;
    }
    _offset-=s;
    return getinsn();
}

template <class insn>
insn vmem<insn>::operator--(){
    auto s = insnSize();
    if (_offset < s){
        //prev seg
        retcustomassure(out_of_range, _segNum>0, "underflow reached end of vmem");
        _segNum--;
        _offset = curSeg()->size;
    }
    _offset-=s;
    return getinsn();
}

template <>
vmem<arm32::thumb> &vmem<arm32::thumb>::operator+=(int i);
template <>
vmem<arm32::thumb> &vmem<arm32::thumb>::operator-=(int i);

template <>
vmem<arm32::thumb> &vmem<arm32::thumb>::operator+=(int i){
    if (i<0) return operator-=(-i);
    //i is always positive

    size_t curSegSize = curSeg()->size;
    
    for (;i>0;i--) {
        uint8_t s = 2;
        _offset+=s;
        if (s >= _offset+curSegSize){
            //next seg
            const pvsegment *nseg = _segments.get()[_segNum+1];
            retcustomassure(out_of_range, nseg, "overflow reached end of vmem");
            _segNum++;
            _offset = 0;
            curSegSize = curSeg()->size;
        }
    }
    return *this;
}

template <class insn>
vmem<insn> &vmem<insn>::operator+=(int i){
    if (i<0) return operator-=(-i);
    //i is always positive

    size_t curSegSize = curSeg()->size;
    
    for (;i>0;i--) {
        auto s = insnSize();
        _offset+=s;
        if (s >= _offset+curSegSize){
            //next seg
            const pvsegment *nseg = _segments.get()[_segNum+1];
            retcustomassure(out_of_range, nseg, "overflow reached end of vmem");
            _segNum++;
            _offset = 0;
            curSegSize = curSeg()->size;
        }
    }
    return *this;
}

template <>
vmem<arm32::thumb> &vmem<arm32::thumb>::operator-=(int i){
    if (i<0) return operator+=(-i);
    //i is always positive
    uint8_t s = 2;
    for (;i>0;i--) {
        if (_offset < s){
            //prev seg
            retcustomassure(out_of_range, _segNum>0, "underflow reached end of vmem");
            _segNum--;
            _offset = curSeg()->size;
        }
        _offset-=s;
    }
    return *this;
}

template <class insn>
vmem<insn> &vmem<insn>::operator-=(int i){
    if (i<0) return operator+=(-i);
    //i is always positive
    uint8_t s = insnSize();
    for (;i>0;i--) {
        if (_offset < s){
            //prev seg
            retcustomassure(out_of_range, _segNum>0, "underflow reached end of vmem");
            _segNum--;
            _offset = curSeg()->size;
        }
        _offset-=s;
    }
    return *this;
}

template <class insn>
insn vmem<insn>::operator+(int i){
    if (i<0) return operator-(-i);
    //i is always positive
    
    size_t offset = _offset;
    uint32_t segNum = _segNum;
    cleanup([&]{
        _offset = offset;
        _segNum = segNum;
    });
    *this += i;
    return getinsn();
}

template <class insn>
insn vmem<insn>::operator-(int i){
    if (i<0) return operator+(-i);
    //i is always positive
    
    size_t offset = _offset;
    uint32_t segNum = _segNum;
    cleanup([&]{
        _offset = offset;
        _segNum = segNum;
    });
    *this -= i;
    return getinsn();
}


template <class insn>
vmem<insn> &vmem<insn>::operator=(typename insn::loc_t pos){
    if (pos == 0) {
        _segNum = 0;
        _offset = 0;
        return *this;
    }
    
    uint32_t tgtSegNum = 0;
    for (pvsegment **s = _segments.get(); *s; s++,tgtSegNum++) {
        pvsegment *seg = *s;
        if (isInSegRange(seg, pos)) {
            _segNum = tgtSegNum;
            _offset = pos-seg->vaddr;
            return *this;
        }
    }
    retcustomerror(out_of_range, "loc not within vmem");
}

#pragma mark segment info functions
template <class insn>
int vmem<insn>::curPerm() const{
    const pvsegment *seg = curSeg();
    return seg->perms;
}

template <class insn>
const void *vmem<insn>::memoryForLoc(typename insn::loc_t loc) const{
    const pvsegment *seg = segmentForLoc(loc);
    return seg->buf+(loc-seg->vaddr);
}


#pragma mark deref operator
template <class insn>
typename insn::loc_t vmem<insn>::pc() const{
    return (typename insn::loc_t)(_segments.get()[_segNum]->vaddr+_offset);
}

template <class insn>
uint32_t vmem<insn>::value() const{
    const pvsegment *seg = curSeg();
    customassure(out_of_range,_offset + sizeof(uint32_t) <= seg->size);
    return *(uint32_t*)&seg->buf[_offset];
}

template <class insn>
uint64_t vmem<insn>::doublevalue() const{
    const pvsegment *seg = curSeg();
    customassure(out_of_range, _offset + sizeof(uint64_t) <= seg->size);
    return *(uint64_t*)&seg->buf[_offset];
}

template <class insn>
uint32_t vmem<insn>::value(typename insn::loc_t p) const{
    const pvsegment *seg = segmentForLoc(p);
    uint64_t offset = p - seg->vaddr;
    customassure(out_of_range, offset + sizeof(uint32_t) <= seg->size);
    return *(uint32_t*)&seg->buf[offset];
}

template <class insn>
uint64_t vmem<insn>::doublevalue(typename insn::loc_t p) const{
    const pvsegment *seg = segmentForLoc(p);
    uint64_t offset = p - seg->vaddr;
    customassure(out_of_range, offset + sizeof(uint64_t) <= seg->size);
    return *(uint64_t*)&seg->buf[offset];
}

#pragma mark insn operator
template <class insn>
insn vmem<insn>::getinsn() const{
    return insn(value(),pc());
}

template <class insn>
insn vmem<insn>::operator()(){
    return getinsn();
}

template <class insn>
vmem<insn>::operator typename insn::loc_t() const{
    auto seg = curSeg();
    return (typename insn::loc_t)(seg->vaddr + _offset);
}


#pragma mark explicit instantiation
template class tihmstar::libinsn::vmem<arm64::insn>;
template class tihmstar::libinsn::vmem<arm32::arm>;
template class tihmstar::libinsn::vmem<arm32::thumb>;

//copy constructor default
template vmem<arm32::arm>::vmem(const vmem<arm32::thumb> &cpy, arm32::arm::loc_t pos, int perm);
template vmem<arm32::thumb>::vmem(const vmem<arm32::arm> &cpy, arm32::thumb::loc_t pos, int perm);

//copy constructor with pointer
template vmem<arm32::arm>::vmem(const vmem<arm32::thumb> *cpy, arm32::arm::loc_t pos, int perm);
template vmem<arm32::thumb>::vmem(const vmem<arm32::arm> *cpy, arm32::thumb::loc_t pos, int perm);

template vmem<arm32::arm> &vmem<arm32::arm>::operator=(const vmem<arm32::thumb> &cpy);
template vmem<arm32::thumb> &vmem<arm32::thumb>::operator=(const vmem<arm32::arm> &cpy);
