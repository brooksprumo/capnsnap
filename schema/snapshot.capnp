@0xcbcf473fa70293d2;

using Rust = import "rust.capnp";

struct Snapshot {
    bank               @0 :Bank;
    accountsDeltaHash  @1 :Hash; # TODO: move into Bank? Remove entirely?
    accountsHash       @2 :Hash $Rust.option;
    accountStorages    @3 :List(AccountStorage);

    # status cache
    # epoch accounts hash
    # accounts db
    #    - accounts storage files
    #    - accounts hash
    #    - accounts delta hash (is this actually needed...?)
    #    - bank stats??? (is this actually needed...?)
}

struct Bank {
    epoch               @0  :UInt64;
    blockHeight         @1  :UInt64;
    slot                @2  :UInt64;
    hash                @3  :Hash;
    epochAccountsHash   @4  :Hash $Rust.option; # TODO: move out of Bank
    parentSlot          @5  :UInt64;
    parentHash          @6  :Hash;
    transactionCount    @7  :UInt64;
    tickHeight          @8  :UInt64;
    maxTickHeight       @9  :UInt64;
    hashesPerTick :union {
        none @10 :Void;
        some @11 :UInt64;
    }
    ticksPerSlot        @12 :UInt64;
    nsPerSlot           @13 :UInt64; # NOTE: originally a u128
    slotsPerYear        @14 :Float64;
    signatureCount      @15 :UInt64;
    capitalization      @16 :UInt64;
    isDelta             @17 :Bool;
    accountsDataSize    @18 :UInt64;
    collectorId         @19 :Pubkey;
    collectorFees       @20 :UInt64;
    collectedRent       @21 :UInt64;
    genesisCreationTime @22 :UInt64; # NOTE: originally an i64
    inflation           @23 :Inflation;
    hardForks           @24 :List(HardFork);
    feeRateGovernor     @25 :FeeRateGovernor;
    incrementalSnapshotPersistence @26 :IncrementalSnapshotPersistence $Rust.option; # TODO: move out of Bank
    rentCollector       @27 :RentCollector;
    ancestors           @28 :List(UInt64);
    epochSchedule       @29 :EpochSchedule;
    blockhashQueue      @30 :BlockhashQueue;
    stakes              @31 :Stakes;
    epochStakes         @32 :List(EpochStake);
    epochRewards        @33 :EpochRewards $Rust.option;

    # TODO: add lamports per signature?

    # fee_calculator: FeeCalculator, # TODO: unused? need to confirm
}

struct Hash {
    bytes @0 :Data;
}

struct AccountStorage {
    slot  @0 :UInt64;
    id    @1 :UInt32;
    count @2 :UInt64; # number of accounts in this file
}

struct Pubkey {
    bytes @0 :Data;
}

struct Account {
    lamports   @0 :UInt64;
    data       @1 :Data;
    owner      @2 :Pubkey;
    executable @3 :Bool;
    rentEpoch  @4 :UInt64;
}

struct Inflation {
    initial        @0 :Float64;
    terminal       @1 :Float64;
    taper          @2 :Float64;
    foundation     @3 :Float64;
    foundationTerm @4 :Float64;
}

struct HardFork {
    slot  @0 :UInt64;
    count @1 :UInt64;
}

struct FeeRateGovernor {
  lamportsPerSignature       @0 :UInt64;
  targetLamportsPerSignature @1 :UInt64;
  targetSignaturesPerSlot    @2 :UInt64;
  minLamportsPerSignature    @3 :UInt64;
  maxLamportsPerSignature    @4 :UInt64;
  burnPercent                @5 :UInt8;
}

struct IncrementalSnapshotPersistence {
    fullSlot                  @0 :UInt64;
    fullHash                  @1 :Hash;
    fullCapitalization        @2 :UInt64;
    incrementalHash           @3 :Hash;
    incrementalCapitalization @4 :UInt64;
}

struct RentCollector {
    epoch         @0 :UInt64;
    epochSchedule @1 :EpochSchedule;
    slotsPerYear  @2 :Float64;
    rent          @3 :Rent;
}

struct Rent {
    lamportsPerByteYear @0 :UInt64;
    exemptionThreshold  @1 :Float64;
    burnPercent         @2 :UInt8;
}

struct EpochSchedule {
    slotsPerEpoch            @0 :UInt64;
    leaderScheduleSlotOffset @1 :UInt64;
    warmup                   @2 :Bool;
    firstNormalEpoch         @3 :UInt64;
    firstNormalSlot          @4 :UInt64;
}

struct BlockhashQueue {
    lastHashIndex @0 :UInt64;
    lastHash      @1 :Hash $Rust.option;
    maxAge        @2 :UInt64;
    ages          @3 :List(Age);

    struct Age {
        hashIndex     @0 :UInt64;
        hash          @1 :Hash;
        timestamp     @2 :UInt64;
        feeCalculator @3 :FeeCalculator;
    }
}

struct FeeCalculator {
    lamportsPerSignature @0 :UInt64;
}

struct Stakes {
    epoch            @0 :UInt64;
    voteAccounts     @1 :List(VoteAccountsEntry);
    stakeDelegations @2 :List(StakeDelegationsEntry);
    stakeHistory     @3 :List(StakeHistoryEntry);

    struct VoteAccountsEntry {
        pubkey  @0 :Pubkey;
        stake   @1 :UInt64;
        account @2 :Account;
    }
    struct StakeDelegationsEntry {
        stakePubkey        @0 :Pubkey;
        voterPubkey        @1 :Pubkey;
        stake              @2 :UInt64;
        activationEpoch    @3 :UInt64;
        deactivationEpoch  @4 :UInt64;
        warmupCooldownRate @5 :Float64;
    }
    struct StakeHistoryEntry {
        epoch        @0 :UInt64;
        effective    @1 :UInt64;
        activating   @2 :UInt64;
        deactivating @3 :UInt64;
    }
}

struct EpochStake {
    epoch                 @0 :UInt64;
    totalStake            @1 :UInt64;
    stakes                @2 :Stakes;
    nodeIdsToVoteAccounts @3 :List(NodeIdToVoteAccounts);
    epochAuthorizedVoters @4 :List(EpochAuthorizedVoter);

    struct NodeIdToVoteAccounts {
        nodeId       @0 :Pubkey;
        totalStake   @1 :UInt64;
        voteAccounts @2 :List(Pubkey);
    }
    struct EpochAuthorizedVoter {
        voteAccount     @0 :Pubkey;
        authorizedVoter @1 :Pubkey;
    }
}

struct EpochRewards {
    startBlockHeight  @0 :UInt64;
    epochStakeRewards @1 :List(EpochStakeReward);

    struct EpochStakeReward {
        stakePubkey     @0 :Pubkey;
        stakeAccount    @1 :Account;
        stakeRewardInfo @2 :RewardInfo;

        struct RewardInfo {
            rewardKind  @0 :RewardKind;
            lamports    @1 :UInt64;
            postBalance @2 :UInt64;
            commission :union {
                none    @3 :Void;
                some    @4 :UInt8;
            }
        }
    }
}

enum RewardKind {
    fee     @0;
    rent    @1;
    staking @2;
    voting  @3;
}
