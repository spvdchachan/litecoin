// Copyright (c) 2012 Pieter Wuille
// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <paddrman.h>

bool CPAddr::IsTerrible(int64_t nNow) const
{
    // We can decide the criteria later.
    return false;
}

CPAddr* CPAddrMan::Find(const std::string& addrKey)
{
    auto it = addrMap.find(addrKey);
    if (it == addrMap.end())
        return nullptr;
    return &(*it).second;
}

CPAddr* CPAddrMan::Create(const CAddress &addr, const CNetAddr& addrSource)
{
    std::string addrKey = addr.ToString();
    addrMap[addrKey] = CPAddr(addr, addrSource);
    addrMap[addrKey].nRandomPos = vRandom.size();
    vRandom.push_back(addrKey);
    newSet.insert(addrKey);
    return &addrMap[addrKey];
}

void CPAddrMan::Delete(const std::string& addr)
{
    assert(addrMap.count(addr) != 0);
    CPAddr& info = addrMap[addr];
    SwapRandom(info.nRandomPos, vRandom.size() - 1);
    vRandom.pop_back();
    addrMap.erase(info.ToString());
    
    if (info.fInReconn){
        reconnSet.erase(info.ToString());
    } else {
        newSet.erase(info.ToString());
    }
    LogPrintf("Passive: address=%s;unreachable\n", info.ToString());
}

void CPAddrMan::SwapRandom(unsigned int nRndPos1, unsigned int nRndPos2)
{
    if (nRndPos1 == nRndPos2)
        return;
    
    assert(nRndPos1 < vRandom.size() && nRndPos2 < vRandom.size());
    
    std::string addr1 = vRandom[nRndPos1];
    std::string addr2 = vRandom[nRndPos2];
    
    addrMap[addr1].nRandomPos = nRndPos2;
    addrMap[addr2].nRandomPos = nRndPos1;
    
    vRandom[nRndPos1] = addr2;
    vRandom[nRndPos2] = addr1;
}

bool CPAddrMan::Add_(const CAddress& addr, const CNetAddr& source, int64_t nTimePenalty)
{
    if (!addr.IsRoutable())
        return false;
        
    bool fNew = false;
    CPAddr* pinfo = Find(addr.ToString());
    
    // Do not set a penalty for a source's self-announcement
    if (addr == source)
        nTimePenalty = 0;
    
    if (pinfo)
    {
        // periodically update nTime
        bool fCurrentlyOnline = (GetAdjustedTime() - addr.nTime < 24 * 60 * 60);
        int64_t nUpdateInterval = (fCurrentlyOnline ? 60 * 60 : 24 * 60 * 60);
        if (addr.nTime && (!pinfo->nTime || pinfo->nTime < addr.nTime - nUpdateInterval - nTimePenalty))
            pinfo->nTime = std::max((int64_t)0, addr.nTime - nTimePenalty);
        
        // add services
        pinfo->nServices = ServiceFlags(pinfo->nServices | addr.nServices);
        
        // do not update if no new information is present
        if (!addr.nTime || (pinfo->nTime && addr.nTime <= pinfo->nTime))
            return false;
    }
    else 
    {
        pinfo = Create(addr, source);
        pinfo->nTime = std::max((int64_t)0, (int64_t)pinfo->nTime - nTimePenalty);
        fNew = true;
//        LogPrintf("Passive: discover address=%s;source=%s\n", addr.ToString(), source.ToString());
        // Discovery 
        LogDiscovery(addr.ToString(), source.ToString());
    }
    
    return fNew;
}

void CPAddrMan::Good_(const CService& addr, int64_t nTime)
{
    CPAddr* pinfo = Find(addr.ToString());
    
    // if not found, bail out
    if (!pinfo) {
        return;
    }
     
    CPAddr& info = *pinfo;
    
    // check whether we are talking about the exact same CService (including same port)
    if (info != addr)
        return;
    
    // update info
    info.nLastSuccess = nTime;
    info.nLastTry = nTime;
    info.nAttempts = 0;
    info.nSuccesses++;
    // nTime is not updated here, to avoid leaking information about
    // currently-connected peers.
    
    if (info.fInReconn)
        return;
    
    info.fInReconn = true;
    reconnSet.insert(info.ToString());
    newSet.erase(info.ToString());
    LogPrint(BCLog::ADDRMAN, "Passive: Added address=%s to reconn\n", info.ToString());
}

void CPAddrMan::Attempt_(const CService& addr, bool fCountFailure, int64_t nTime)
{
    CPAddr* pinfo = Find(addr.ToString());
    
    // if not found, bail out
    if (!pinfo)
        return;
    
    CPAddr& info = *pinfo;
    
    // check whether we are talking about the exact same CService (including same port)
    if (info != addr)
        return;
    
    // update
    info.nLastTry = nTime;
    if (fCountFailure) {
        info.nAttempts++;
        
        // if (info.nAttempts > nAttemptLimit)
        //     Delete(info.ToString());
    }
}

void CPAddrMan::GetAddr_(std::vector<CAddress>& vAddr)
{
    unsigned int nNodes = ADDRMAN_GETADDR_MAX_PCT * vRandom.size() / 100;
    if (nNodes > ADDRMAN_GETADDR_MAX)
        nNodes = ADDRMAN_GETADDR_MAX;
    
    // gather a list of random nodes, skipping those of low quality
    for (unsigned int n = 0; n < vRandom.size(); n++)
    {
        if (vAddr.size() >= nNodes)
            break;
        
        int nRndPos = RandomInt(vRandom.size() - n) + n;
        SwapRandom(n, nRndPos);
        
        const CPAddr& ai = addrMap[vRandom[n]];
        if (!ai.IsTerrible())
            vAddr.push_back(ai);
    }
}

void CPAddrMan::Connected_(const CService& addr, int64_t nTime)
{
    CPAddr* pinfo = Find(addr.ToString());

    // if not found, bail out
    if (!pinfo)
        return;

    CPAddr& info = *pinfo;

    // check whether we are talking about the exact same CService (including same port)
    if (info != addr)
        return;

    // update info
    int64_t nUpdateInterval = 20 * 60;
    if (nTime - info.nTime > nUpdateInterval)
        info.nTime = nTime;
}

void CPAddrMan::SetServices_(const CService& addr, ServiceFlags nServices)
{
    CPAddr* pinfo = Find(addr.ToString());
    
    // if not found, bail out
    if(!pinfo)
        return;
    
    CPAddr& info = *pinfo;
    
    // check whether we are talking about the exact same CService (including same port)
    if (info != addr)
        return;

    // update info
    info.nServices = nServices; 
}


int CPAddrMan::RandomInt(int nMax){
    return GetRandInt(nMax);
}
