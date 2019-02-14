// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PADDRMAN_H
#define BITCOIN_PADDRMAN_H

#include <netaddress.h>
#include <protocol.h>
#include <util.h>
#include <sync.h>
#include <random.h>

#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <vector>
#include <stdint.h>

/** Extends statistics regarding reconnections on CAddress 
 *  Similar to `CAddrInfo` but more lightweight
 */
class CPAddr : public CAddress
{
public:
    //! last connection time
    int64_t nLastSeen;
    
    //! number of successful re-connections
    int64_t nSuccesses;
    
    //! will it be reconnected
    bool fInReconn;
        
private:
    //! where we first heard about the address
    CNetAddr source;
    
    //! when it was created - would like this to be const but don't want to mess around with low-level serialization
    int64_t nCreatedTime;
    
    //! connection attempts since last successful attempt   
    int nAttempts;
    
    //! position in vRandom (memory)
    int nRandomPos;
    
    friend class CPAddrMan;
    
public:
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action){
        READWRITE(*(CAddress*)this);
        READWRITE(nLastSeen);
        READWRITE(nSuccesses);
        READWRITE(fInReconn);
        READWRITE(source)
        READWRITE(nCreatedTime);
        READWRITE(nAttempts);
    }
    
    void Init()
    {
        nCreatedTime = GetSystemTimeInSeconds();
        nSuccesses = 0;
        nLastSeen = 0;
        nAttempts = 0;
        fInReconn = false;
        nRandomPos = -1;
    }
    
    CPAddr(const CAddress &addrIn, const CNetAddr &addrSrc) : 
        CAddress(addrIn), source(addrSrc)
    {
        Init();
    }
    
    CPAddr(const CAddress &addrIn) :
        CAddress(addrIn), source()
    {
        Init();
    }
    
    CPAddr() : CAddress(), source()
    {
        Init();
    }
    
    //! Determine whether the statistics about this entry are bad enough so that it can just be deleted
    bool IsTerrible(int64_t nNow = GetAdjustedTime()) const;
    
};

#define ADDRMAN_GETADDR_MAX_PCT 23
#define ADDRMAN_GETADDR_MAX 2500

/**
 * Passive address manager
 * 
 * This is designed to replace `CAddrMan` which is more complicated
 * and doesn't suit our needs. 
 * Here, it will be more lightweight focusing on two main address types:
 * 1. New addresses: haven't been connected to before or unseen for a long time
 * 2. Reconn addresses: have been connected to recently and ready to be reconnected
 * 
 */
class CPAddrMan 
{
private:  
    //! Protect inner data structures
    mutable CCriticalSection cs;
    
    //! Address store
    std::unordered_map<std::string, CPAddr> addrMap;
    
    //! Reconn index (memory)
    std::unordered_set<std::string> reconnSet;
    
    //! Random keys (memory)
    std::vector<std::string> vRandom;
    
protected:
    
    //! Find an entry.
    CPAddr* Find(const CNetAddr& addr);
    
    //! find an entry, creating it if necessary.
    CPAddr* Create(const CAddress &addr, const CNetAddr &addrSource);
    //! Delete
    
    //! Swap two elements in vRandom
    void SwapRandom(unsigned int nRndPos1, unsigned int nRndPos2);
    
    //! Add an entry to the new address set
    bool Add_(const CAddress &addr, const CNetAddr& source, int64_t nTimePenalty);
    
    //! "good", add to reconn set
    void Good_(const CService &addr, int64_t nTime);
    
    //! Select several addresses at once.
    void GetAddr_(std::vector<CAddress> &vAddr);
    
    //! Mark an entry as currently-connected-to.
    void Connected_(const CService &addr, int64_t nTime);
    
    //! Update an entry's service bits.
    void SetServices_(const CService &addr, ServiceFlags nServices);
    
    //! Wraps GetRandInt to allow tests to override RandomInt and make it determinismistic.
    virtual int RandomInt(int nMax);
    
public:
    
    ADD_SERIALIZE_METHODS;
    
    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        LOCK(cs);
        READWRITE(addrMap);
    }
    
    CPAddrMan()
    {
        
    }
    
    ~CPAddrMan(){}
    
    //! Construct containers
    void MakeContainers()
    {
        LOCK(cs);
        reconnSet.clear();
        for(auto it = addrMap.begin(); it != addrMap.end(); it++)
        {
            CPAddr &addr = (*it).second;
            if(addr.fInReconn)
                reconnSet.insert(addr.ToString());
            addr.nRandomPos = vRandom.size();
            vRandom.push_back((*it).first);
        }
    }
    
    //! Add a single address
    bool Add(const CAddress &addr, const CNetAddr& source, int64_t nTimePenalty = 0)
    {
        LOCK(cs);
        bool fRet = false;
        fRet |= Add_(addr, source, nTimePenalty);
        
        if(fRet)
            LogPrint(BCLog::ADDRMAN, "Added %s from %s\n", addr.ToStringIPPort(), source.ToString());
        
        return fRet;
    }
    
    //! Add multiple addresses
    bool Add(const std::vector<CAddress> &vAddr, const CNetAddr& source, int64_t nTimePenalty = 0)
    {
        LOCK(cs);
        int nAdd = 0;
        for (auto it = vAddr.begin(); it != vAddr.end(); it++)
            nAdd += Add_(*it, source, nTimePenalty) ? 1 : 0;
        
        if (nAdd) 
            LogPrint(BCLog::ADDRMAN, "Added %i addresses from %s\n", nAdd, source.ToString());
        
        return nAdd > 0;
    }
    
    //! Mark an entry as accessible so we should reconnect later
    void Good(const CService &addr, int64_t nTime = GetAdjustedTime())
    {
        LOCK(cs);
        Good_(addr, nTime);
    }
    
    //! Return a bunch of addresses, selected at random (used for getaddr)
    std::vector<CAddress> GetAddr()
    {
        std::vector<CAddress> vAddr;
        {
            LOCK(cs);
            GetAddr_(vAddr);
        }
        return vAddr;
    }
    
    //! Mark an entry as currently-connected-to.
    void Connected(const CService &addr, int64_t nTime = GetAdjustedTime())
    {
        LOCK(cs);
        Connected_(addr, nTime);
    }
    
    void SetServices(const CService &addr, ServiceFlags nServices)
    {
        LOCK(cs);
        SetServices_(addr, nServices);
    }
    
};

#endif /* BITCOIN_PADDRMAN_H */
