// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRDB_H
#define BITCOIN_ADDRDB_H

#include <fs.h>
#include <utiltime.h>
#include <protocol.h>

#include <string>
#include <map>
#include <vector>

class CSubNet;
class CAddrMan;
class CDataStream;

typedef enum BanReason
{
    BanReasonUnknown          = 0,
    BanReasonNodeMisbehaving  = 1,
    BanReasonManuallyAdded    = 2
} BanReason;

class CBanEntry
{
public:
    static const int CURRENT_VERSION=1;
    int nVersion;
    int64_t nCreateTime;
    int64_t nBanUntil;
    uint8_t banReason;

    CBanEntry()
    {
        SetNull();
    }

    explicit CBanEntry(int64_t nCreateTimeIn)
    {
        SetNull();
        nCreateTime = nCreateTimeIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(nCreateTime);
        READWRITE(nBanUntil);
        READWRITE(banReason);
    }

    void SetNull()
    {
        nVersion = CBanEntry::CURRENT_VERSION;
        nCreateTime = 0;
        nBanUntil = 0;
        banReason = BanReasonUnknown;
    }

    std::string banReasonToString() const
    {
        switch (banReason) {
        case BanReasonNodeMisbehaving:
            return "node misbehaving";
        case BanReasonManuallyAdded:
            return "manually added";
        default:
            return "unknown";
        }
    }
};

typedef std::map<CSubNet, CBanEntry> banmap_t;

/** Access to the (IP) address database (peers.dat) */
class CAddrDB
{
private:
    fs::path pathAddr;
public:
    CAddrDB();
    bool Write(const CAddrMan& addr);
    bool Read(CAddrMan& addr);
    static bool Read(CAddrMan& addr, CDataStream& ssPeers);
};

/** Access to the banlist database (banlist.dat) */
class CBanDB
{
private:
    fs::path pathBanlist;
public:
    CBanDB();
    bool Write(const banmap_t& banSet);
    bool Read(banmap_t& banSet);
};

// PASSIVE
/** Extends statistics regarding reconnections on CAddress */
class CReconnAddr : public CAddress
{
public:
    //! last connection time
    int64_t nLastSeen;
    
private:
    //! when it was created - would like this to be const but don't want to mess around with low-level serialization
    int64_t nCreatedTime;
    
public:
    
    ADD_SERIALIZE_METHODS;
    
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action){
        READWRITE(*(CAddress*)this);
        READWRITE(nCreatedTime);
        READWRITE(nLastSeen);
    }
    
    void Init()
    {
        nCreatedTime = GetSystemTimeInSeconds();
    }
    
    CReconnAddr(const CAddress &addrIn, int64_t nLastSeen) : 
        CAddress(addrIn),
        nLastSeen(nLastSeen)
    {
        Init();
    }
    
    CReconnAddr(const CAddress &addrIn) :
        CAddress(addrIn),
        nLastSeen(GetSystemTimeInSeconds())
    {
        Init();
    }
    
    CReconnAddr() : CAddress(), nLastSeen(GetSystemTimeInSeconds())
    {
        Init();
    }
    
};

typedef std::vector<CReconnAddr> reconn_queue_t;

/** Access to the reconn address database (reconns.dat) */
class CReconnDB
{
private:
    fs::path pathReconn;
public:
    CReconnDB();
    bool Write(const reconn_queue_t& reconnQueue);
    bool Read(reconn_queue_t& reconnQueue);
};

#endif // BITCOIN_ADDRDB_H
